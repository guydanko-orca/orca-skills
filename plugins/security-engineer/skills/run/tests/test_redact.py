#!/usr/bin/env python3
"""
Tests for credential redaction on egress (skills/run/redact.py) and its wiring.

The property under protection is narrow and absolute: for a secret finding, no
path that leaves this process carries the credential. "Leaves" means the two
model prompts, the PR title and body, and the notification payload that reaches
the run log and the webhook.

The commit diff is the deliberate exception — a commit that removes a line
renders that line — so the tests assert the PR body carries the rotation warning
instead, which is what makes the residue honest.

The second property is the inverse, and it is just as load-bearing: a non-secret
finding must be redacted *not at all*, or gate 2 would be judging a diff with its
subject blanked out.

Hermetic: no network, no claude subprocess.

Run with: python3 tests/test_redact.py
"""
import base64
import hashlib
import io
import sys
import unittest
import unittest.mock
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

_DIR = Path(__file__).parent
sys.path.insert(0, str(_DIR.parent))                 # skills/run/
sys.path.insert(0, str(_DIR.parent.parent / "lib"))  # skills/lib/

sys.path.insert(0, str(_DIR))                        # tests/
import _git_sandbox  # (hermetic git config snapshot)
import impact_agent
import orchestrator
import validator
from redact import PLACEHOLDER, Redactor, build_redactor

# A deliberately fake credential in the `sk-live-` shape the redactor is tested
# against. Built at import rather than written out, so the source holds no
# high-entropy literal for a secret scanner to report; hashing a fixed seed keeps
# the value identical on every run.
SECRET = "sk-live-" + hashlib.sha256(b"orca-redact-test-fixture").hexdigest()[:20]

SECRET_ALERT = {
    "alert_id": "orca-abc123",
    "feature_type": "secret",
    "category": "Secrets",
    "code_snippet": [f'API_KEY = "{SECRET}"'],
    "description": "Hardcoded API key",
}

CVE_ALERT = {
    "alert_id": "orca-def456",
    "feature_type": "",
    "category": "Vulnerabilities",
    "code_snippet": ["pillow==8.3.1"],
}


class TestCandidateExtraction(unittest.TestCase):
    def test_assignment_value_is_a_candidate(self):
        self.assertIn(SECRET, build_redactor(SECRET_ALERT).candidates)

    def test_key_is_never_a_candidate(self):
        """The env var name is what the PR must tell an operator to set."""
        self.assertNotIn("API_KEY", build_redactor(SECRET_ALERT).candidates)

    def test_whole_line_is_a_candidate(self):
        """The form a unified diff actually contains."""
        self.assertIn(f'API_KEY = "{SECRET}"', build_redactor(SECRET_ALERT).candidates)

    def test_bare_env_assignment(self):
        """.env and Dockerfile ENV lines have no quotes to anchor on."""
        alert = dict(SECRET_ALERT, code_snippet=[f"API_KEY={SECRET}"])
        self.assertIn(SECRET, build_redactor(alert).candidates)

    def test_candidates_are_longest_first(self):
        lengths = [len(c) for c in build_redactor(SECRET_ALERT).candidates]
        self.assertEqual(lengths, sorted(lengths, reverse=True))

    def test_short_values_are_not_candidates(self):
        """Below the floor a candidate matches prose, not a credential."""
        alert = dict(SECRET_ALERT, code_snippet=['x = "ab"'])
        self.assertNotIn("ab", build_redactor(alert).candidates)

    def test_non_secret_alert_gets_null_redactor(self):
        r = build_redactor(CVE_ALERT)
        self.assertFalse(r)
        self.assertEqual(r("pillow==8.3.1 is vulnerable"), "pillow==8.3.1 is vulnerable")

    def test_none_alert_is_safe(self):
        self.assertFalse(build_redactor(None))


# Shapes a masked code_snippet could take. Unverified against the live API —
# nothing in this repository shows Orca's secret snippet either way — so the
# redactor has to be safe for both.
MASKED_SNIPPETS = [
    ("asterisks in the value",  ['API_KEY = "sk-****"']),
    ("partially starred",       ['aws_secret = "AKIA************WXYZ"']),
    ("fully starred",           ['password: "**************"']),
    ("bullet mask",             ['TOKEN = "••••••••••"']),
    ("redacted marker",         ['API_KEY = "[REDACTED]"']),
    ("trailing dots",           ['GITHUB_TOKEN = "ghp_ab12...."']),
    ("ellipsis",                ['aws_key = "AKIA12345…"']),
    ("x-run",                   ['STRIPE_KEY = "sk-xxxxx12345"']),
    ("hash run",                ['DB_PASSWORD = "################"']),
    ("angle placeholder",       ['SLACK_TOKEN = "<hidden-value>"']),
    ("ordinary-looking value",  ['DB_PASS = "correcthorse"']),
    ("no snippet at all",       []),
    ("only a short value",      ['x = "ab"']),
]

# A high-entropy credential with no name a pattern can anchor on. Derived, like
# SECRET, so the source holds no literal for a scanner to flag.
UNLABELLED = base64.b64encode(hashlib.sha256(b"orca-redact-unlabelled").digest()).decode()[:32]


class TestMaskedSnippetFallsBackToPatterns(unittest.TestCase):
    """Candidates come from code_snippet. If Orca masks the value there, every
    candidate is a string that never appears anywhere and the redactor matched
    nothing — silently, with no sign that it had."""

    def _alert(self, snippet):
        return dict(SECRET_ALERT, code_snippet=snippet)

    def test_masked_or_empty_snippet_gets_a_live_fallback(self):
        for desc, snippet in MASKED_SNIPPETS:
            with self.subTest(desc):
                r = build_redactor(self._alert(snippet))
                self.assertTrue(r, desc)
                self.assertTrue(r.fallback_reason, desc)
                self.assertFalse([c for c in r.candidates if "*" in c or "•" in c],
                                 f"{desc}: a masked candidate matches nothing")

    def test_fallback_scrubs_the_credential_from_a_diff_and_keeps_the_key(self):
        r = build_redactor(self._alert(['API_KEY = "sk-****"']))
        out = r(f'-API_KEY = "{SECRET}"\n+API_KEY = os.environ["API_KEY"]')
        self.assertNotIn(SECRET, out)
        self.assertIn(PLACEHOLDER, out)
        self.assertIn('-API_KEY = "', out, "keys are never redacted")
        self.assertIn('os.environ["API_KEY"]', out, "the fix side must survive")

    def test_fallback_scrubs_known_token_shapes(self):
        r = build_redactor(self._alert([]))
        token = "sk-" + hashlib.sha256(b"sk-shape").hexdigest()[:32]
        bearer = hashlib.sha256(b"bearer-shape").hexdigest()[:32]
        for text, secret in ((f"key is {token}", token),
                             (f"Authorization: Bearer {bearer}", bearer),
                             (f'creds = ["{UNLABELLED}"]', UNLABELLED)):
            with self.subTest(secret[:6]):
                self.assertNotIn(secret, r(text))

    def test_fallback_leaves_prose_and_names_alone(self):
        r = build_redactor(self._alert([]))
        prose = ("Rotate the exposed credential, then set API_KEY and "
                 "AWS_SECRET_ACCESS_KEY in the deployment environment.")
        self.assertEqual(r(prose), prose)

    def test_fallback_leaves_fence_tags_intact(self):
        """The redactor runs over the whole fenced validation prompt."""
        from untrusted import fence, new_nonce, preamble
        nonce = new_nonce()
        prompt = preamble(nonce) + fence("diff", f'-API_KEY = "{SECRET}"', nonce)
        out = build_redactor(self._alert([]))(prompt)
        self.assertNotIn(SECRET, out)
        self.assertIn(f'<untrusted-{nonce} id="diff">', out)
        self.assertIn(f"</untrusted-{nonce}>", out)
        self.assertIn(f"untrusted-{nonce} id=", preamble(nonce))
        self.assertEqual(out.count(f"untrusted-{nonce}"), prompt.count(f"untrusted-{nonce}"))

    def test_an_unterminated_quote_cannot_swallow_the_prompt(self):
        """The fallback runs over whole fenced prompts. A value pattern that could
        cross a newline ran from an unclosed quote in the diff to the next quote
        anywhere after it — eating the fence's closing tag and the instructions."""
        diff = '+  token = "abcdefghijklmnop\n+other = 1\n'
        with patch.object(validator, "worktree_diff", return_value=diff), \
             patch.object(validator.subprocess, "run") as run, \
             redirect_stdout(io.StringIO()):
            run.return_value.returncode = 0
            run.return_value.stdout = '{"verdict": "pass"}'
            validator.llm_validate(self._alert(['token = "****"']), Path("/tmp/x"))
        prompt = run.call_args.kwargs["input"]
        tag = prompt.split("<untrusted-")[1].split(" ")[0]
        from untrusted import preamble
        self.assertEqual(prompt.count(f"</untrusted-{tag}>"),
                         preamble(tag).count(f"</untrusted-{tag}>") + 2,
                         "alert_json and diff fences both still close")
        self.assertIn("Return ONLY this JSON", prompt)
        self.assertIn('"verdict": "pass|fail|uncertain"', prompt)
        self.assertIn("+other = 1", prompt)

    def test_no_secret_pattern_matches_across_a_newline(self):
        import redact
        for text in ('token = "abcdefgh\nijklmnop"', "Bearer\n" + "A" * 24):
            for pattern in redact.SECRET_PATTERNS:
                with self.subTest(text=text[:10], pattern=pattern[:20]):
                    match = __import__("re").search(pattern, text)
                    self.assertTrue(match is None or "\n" not in match.group(0))

    def test_fallback_reason_carries_no_snippet_content(self):
        r = build_redactor(self._alert(['API_KEY = "sk-li****"']))
        self.assertNotIn("sk-li", r.fallback_reason)

    def test_angle_brackets_in_code_are_not_a_mask(self):
        """Only a value that is a placeholder counts; generics on the line do not."""
        alert = self._alert([f'Map<String, String> env = Map.of("API_KEY", "{SECRET}");'])
        r = build_redactor(alert)
        self.assertIsNone(r.fallback_reason)
        self.assertIn(SECRET, r.candidates)

    def test_a_usable_snippet_needs_no_fallback(self):
        r = build_redactor(SECRET_ALERT)
        self.assertIsNone(r.fallback_reason)
        self.assertIn(SECRET, r.candidates)

    def test_surviving_candidates_still_apply_alongside_patterns(self):
        """A masked line can still carry a literal worth scrubbing exactly."""
        alert = self._alert([f'connect("{SECRET}", password="****")'])
        r = build_redactor(alert)
        self.assertTrue(r.fallback_reason)
        self.assertIn(SECRET, r.candidates)
        self.assertNotIn(SECRET, r(f"uses {SECRET}"))

    def test_non_secret_alert_stays_untouched_even_with_no_snippet(self):
        r = build_redactor(dict(CVE_ALERT, code_snippet=[]))
        self.assertFalse(r)
        self.assertIsNone(r.fallback_reason)

    def test_the_sanity_gate_and_the_fallback_share_one_pattern_list(self):
        import redact
        self.assertIs(validator._SECRET_PATTERNS, redact.SECRET_PATTERNS)

    def test_masked_secret_alert_is_flagged_for_review(self):
        """The fallback can miss a credential no pattern recognises, so the PR
        has to say that redaction ran blind."""
        from impact_agent import ImpactResult
        from orca_client import Repository
        from validator import ValidationResult

        task = orchestrator.AlertTask(
            alert_id="orca-abc123", title="Hardcoded secret", risk_level="high",
            feature_type="secret", source="app.py:14",
            alert_json=self._alert(['API_KEY = "sk-****"']))
        captured = {}

        def open_pr(t, impact, dry_run):
            t.pr_body = captured["body"] = orchestrator._build_pr_body(t, impact)
            return "https://github.com/o/r/pull/1"

        ok = ValidationResult(passed=True, phase="sanity")
        with patch("orchestrator._create_worktree", return_value=Path("/tmp/orca-fix-t")), \
             patch("orchestrator._remove_worktree"), \
             patch("orchestrator._invoke_fix_agent",
                   return_value=orchestrator.FixAgentResult(
                       success=True, files_changed=["app.py"], diff_summary="moved to env")), \
             patch("orchestrator.sanity_check", return_value=ok), \
             patch("orchestrator.llm_validate",
                   return_value=ValidationResult(passed=True, phase="llm", outcome="pass")), \
             patch("pipelines.base.local_build_check", return_value=ok), \
             patch("orchestrator._get_diff", return_value="diff"), \
             patch("orchestrator.analyze_impact", return_value=ImpactResult(
                 level="low", description="", downtime_risk=False, requires_deploy=True)), \
             patch("orchestrator._commit_and_pr", side_effect=open_pr), \
             patch("orchestrator.orca_check_gate",
                   return_value=ValidationResult(passed=True, phase="orca_check")), \
             patch("orchestrator.ci_gate", return_value=ValidationResult(passed=True, phase="ci")), \
             patch("orchestrator.subprocess.run") as gh, \
             redirect_stdout(io.StringIO()):
            gh.return_value.returncode = 0
            result = orchestrator.run_one(task, dry_run=False, notifier=unittest.mock.MagicMock(),
                                          repo=Repository(name="o/r", url="https://github.com/o/r"))
        self.assertTrue(result.needs_review)
        self.assertTrue(any("masked" in r for r in result.review_reasons), result.review_reasons)
        self.assertIn("masked", captured["body"])


class TestEntropyHeuristicRates(unittest.TestCase):
    """The fallback's random-token check, measured rather than asserted on one
    example. A single bits-per-character floor was backwards: hex tops out at 4
    bits, so 3.8 missed most random hex keys while path-like tokens such as
    `fix/orca-12345678-abcdef` cleared it and were blanked from gate 2."""

    @staticmethod
    def _rate(alphabet, length, n=1000):
        import random

        from redact import _looks_random
        rng = random.Random(7)
        return sum(_looks_random("".join(rng.choice(alphabet) for _ in range(length)))
                   for _ in range(n)) / n

    def test_random_keys_are_caught(self):
        import string
        hexdigits = "0123456789abcdef"
        b64 = string.ascii_letters + string.digits + "+/"
        alnum = string.ascii_letters + string.digits
        for desc, alphabet, length, floor in (
                ("hex 20", hexdigits, 20, 0.95), ("hex 32", hexdigits, 32, 0.99),
                ("base64 32", b64, 32, 0.93), ("base64 40", b64, 40, 0.97),
                ("alnum 20", alnum, 20, 0.95), ("alnum 40", alnum, 40, 0.97),
                ("base64 20", b64, 20, 0.75)):
            with self.subTest(desc):
                self.assertGreaterEqual(self._rate(alphabet, length), floor, desc)

    BENIGN = ["fix/orca-12345678-abcdef", "src/config/credentials_v2",
              "package-lock-v3-entry", "123e4567-e89b-12d3-a456-426614174000",
              "test_redact_fallback_secret_2", "HttpClientConnectionPool2",
              "ValidationResultV2Factory", "AbstractSingletonProxyFactoryBean2",
              "getUserById2FromCache", "MAX_RETRY_COUNT_V2_ENABLED",
              "node_modules/@babel/core-7.22.1"]

    def test_names_paths_and_digests_are_not_taken_for_keys(self):
        from redact import _looks_random
        for token in self.BENIGN:
            with self.subTest(token):
                self.assertFalse(_looks_random(token), token)

    @staticmethod
    def _hex(rng, length):
        return "".join(rng.choice("0123456789abcdef") for _ in range(length))

    def _scrub_rate(self, template, length, n=500):
        import random
        rng = random.Random(3)
        r = build_redactor(dict(SECRET_ALERT, code_snippet=[]))
        hits = 0
        for _ in range(n):
            value = self._hex(rng, length)
            hits += value not in r(template.format(value))
        return hits / n

    def test_unquoted_key_assignment_is_caught_at_any_length(self):
        """`-KEY=<hex>` went from always caught to never after the part split,
        because `=` did not separate the name from the value."""
        for length in (8, 12, 16, 20, 32, 40, 64):
            for template in ("-KEY={}", "+DEPLOY_TOKEN={}", "-  api_secret: {}"):
                with self.subTest(template=template, length=length):
                    self.assertEqual(self._scrub_rate(template, length), 1.0)

    def test_bare_digest_length_hex_is_caught_without_git_context(self):
        """40 and 64 hex characters are a SHA only when something says so."""
        for length in (40, 64):
            for template in ("rotate {} now", "-{}", 'creds = ["{}"]'):
                with self.subTest(template=template, length=length):
                    self.assertGreaterEqual(self._scrub_rate(template, length), 0.99)

    def test_git_and_lockfile_digests_survive(self):
        import random
        rng = random.Random(5)
        r = build_redactor(dict(SECRET_ALERT, code_snippet=[]))
        sha, sha2, sha256 = self._hex(rng, 40), self._hex(rng, 40), self._hex(rng, 64)
        for line in (f"index {sha}..{sha2} 100644", f"commit {sha}",
                     f"Merge: {sha} {sha2}", f"github.com/o/r@{sha}",
                     f'"resolved": "git+https://github.com/o/r.git#{sha}"',
                     f"  revision: {sha}", f'checksum = "{sha256}"',
                     f"  sha: {sha}", f"tree {sha}", f"parent {sha}"):
            with self.subTest(line=line[:16]):
                self.assertEqual(r(line), line)

    def test_scrubbing_hostile_lines_takes_linear_time(self):
        """Diff context is attacker-written and is scrubbed before any bound. The
        first unquoted-assignment pattern took minutes on `key-` * 5000."""
        import time
        r = build_redactor(dict(SECRET_ALERT, code_snippet=[]))
        for text in ("key-" * 5000, "a-" * 10000 + "key", "token='" * 3000,
                     "KEY=" * 5000, "ab1-" * 5000 + "=x", "x" * 20000):
            with self.subTest(text=text[:8]):
                started = time.monotonic()
                r(text)
                self.assertLess(time.monotonic() - started, 1.0)

    def test_a_code_reference_on_the_right_is_not_a_value(self):
        """Redacting the fix line would blind gate 2 to the fix."""
        r = build_redactor(dict(SECRET_ALERT, code_snippet=[]))
        for line in ('+API_KEY = os.environ["API_KEY"]', "+KEY=process.env.KEY",
                     "+token = getToken()", "+SECRET=${SECRET}"):
            with self.subTest(line):
                self.assertEqual(r(line), line)

    def test_subresource_integrity_is_not_a_key(self):
        from redact import _looks_random
        digest = base64.b64encode(hashlib.sha512(b"lockfile").digest()).decode()
        self.assertFalse(_looks_random(f"sha512-{digest}"))

    def test_the_alerts_own_file_path_survives(self):
        """A random-looking path component is still the file gate 2 must see."""
        name = base64.b64encode(hashlib.sha256(b"asset-name").digest()).decode()[:22]
        name = name.replace("/", "x").replace("+", "y")
        path = f"assets/{name}.json"
        alert = dict(SECRET_ALERT, code_snippet=[], file_path=path, source=f"{path}:3")
        self.assertIn(path, build_redactor(alert)(f"+++ b/{path}"))
        self.assertNotIn(name, build_redactor(dict(SECRET_ALERT, code_snippet=[]))(
            f"+++ b/{path}"), "without the alert naming it, it does look random")


class TestRedactionTimeIsBounded(unittest.TestCase):
    """Everything the fallback scrubs — diffs, prompts, build output, model prose —
    and the snippet it derives candidates from can be attacker-written. Shapes
    that do not end at `$` defeated lookahead-anchored patterns: `"a=" * N + "."`
    took 68 s at 100 KB. Each case runs in a child process with a hard timeout,
    so a regression fails instead of hanging the suite."""

    SHAPES = {
        "assign-then-dot": '"a=" * {n} + "."',
        "hyphen-run": '"a-" * {n}',
        "key-equals": '"KEY=" * {n} + "x"',
        "hex-run": '"0123456789abcdef" * ({n} // 8)',
        "equals-run": '"=" * ({n} * 2)',
        "dash-run": '"-" * ({n} * 2)',
        "quote-run": '"token=\'" * ({n} // 3)',
        # 40-hex tokens: each one asks for its line's digest context.
        "digest-line": '("0123456789abcdef" * 2 + "01234567 ") * ({n} // 20)',
    }

    def _elapsed(self, setup, call, n):
        import subprocess
        code = (
            "import sys, time\n"
            f"sys.path[:0] = [{str(_DIR.parent)!r}, {str(_DIR.parent.parent / 'lib')!r}]\n"
            "import redact\n"
            f"{setup}\n"
            f"text = {self.SHAPES_EXPR.format(n=n)}\n"
            "started = time.monotonic()\n"
            f"{call}\n"
            "print(time.monotonic() - started)\n")
        result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True,
                                text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr[-500:])
        return float(result.stdout.strip())

    def _check(self, setup, call):
        import subprocess
        for name, expr in self.SHAPES.items():
            for size in (100_000, 1_000_000):
                with self.subTest(shape=name, size=size):
                    self.SHAPES_EXPR = expr
                    try:
                        took = self._elapsed(setup, call, size // 2)
                    except subprocess.TimeoutExpired:
                        self.fail(f"{name} at {size} bytes ran past 20 s")
                    self.assertLess(took, 1.0, f"{name} at {size} bytes")

    def test_scrubbing_a_hostile_text(self):
        self._check(
            "r = redact.build_redactor({'feature_type': 'secret', 'category': 'Secrets', "
            "'code_snippet': []})",
            "r(text)")

    def test_deriving_candidates_from_a_hostile_snippet(self):
        self._check("", "redact.build_redactor({'feature_type': 'secret', "
                        "'category': 'Secrets', 'code_snippet': [text]})")

    def test_the_sanity_gate_on_a_hostile_added_line(self):
        self._check("import re", "[re.search(p, '+' + text) for p in redact.SECRET_PATTERNS]")


class TestOversizedTextFailsClosed(unittest.TestCase):
    """Past the cap the fallback does not scan, and it does not pass text
    through unscanned either: the rest is withheld, marked as such."""

    def test_the_tail_is_withheld_not_passed_through(self):
        import redact
        r = build_redactor(dict(SECRET_ALERT, code_snippet=[]))
        tail_secret = "tail" + hashlib.sha256(b"tail").hexdigest()
        text = "x " * (redact.REDACT_LIMIT // 2) + f"KEY={tail_secret}\n"
        out = r(text)
        self.assertNotIn(tail_secret, out)
        self.assertIn("withheld", out)
        self.assertLessEqual(len(out), redact.REDACT_LIMIT + 200)

    def test_a_token_cut_by_the_cap_is_withheld_whole(self):
        import redact
        r = build_redactor(dict(SECRET_ALERT, code_snippet=[]))
        secret = base64.b64encode(hashlib.sha512(b"straddle").digest()).decode()
        text = "x " * ((redact.REDACT_LIMIT - 20) // 2) + secret + " end"
        self.assertNotIn(secret[:12], r(text))

    def test_text_under_the_cap_is_unchanged_in_length_class(self):
        r = build_redactor(dict(SECRET_ALERT, code_snippet=[]))
        self.assertEqual(r("plain words here"), "plain words here")

    def test_an_oversized_snippet_line_is_not_trusted_as_a_candidate_source(self):
        import redact
        alert = dict(SECRET_ALERT, code_snippet=[f'API_KEY = "{SECRET}"  # ' + "x" * 10000])
        self.assertTrue(build_redactor(alert).fallback_reason)
        self.assertTrue(redact.MAX_SNIPPET_LINE < 10000)


class TestRedactBeforeTruncate(unittest.TestCase):
    """Slicing first can cut an echoed credential mid-value, leaving a prefix
    that no exact candidate matches. Every capped echo redacts, then cuts."""

    FRAGMENT = SECRET[:10]

    def _straddling(self, cut):
        return "y" * (cut - len(self.FRAGMENT)) + SECRET + " and more text after it"

    def _assert_clean(self, text):
        self.assertNotIn(self.FRAGMENT, text)

    def test_unrecognised_verdict(self):
        raw = '{"result": ' + __import__("json").dumps(
            __import__("json").dumps({"verdict": self._straddling(40)})) + "}"
        with redirect_stdout(io.StringIO()):
            result = validator._parse_llm(raw, build_redactor(SECRET_ALERT))
        self._assert_clean(" ".join(result.failures))

    def test_unparseable_validation_output(self):
        with redirect_stdout(io.StringIO()) as out:
            result = validator._parse_llm(self._straddling(200), build_redactor(SECRET_ALERT))
        self._assert_clean(" ".join(result.failures))
        self._assert_clean(out.getvalue())

    def test_validation_cli_error(self):
        with patch.object(validator, "worktree_diff", return_value="d"), \
             patch.object(validator.subprocess, "run") as run, \
             redirect_stdout(io.StringIO()):
            run.return_value.returncode = 1
            run.return_value.stderr = self._straddling(500)
            run.return_value.stdout = ""
            result = validator.llm_validate(SECRET_ALERT, Path("/tmp/x"))
        self._assert_clean(" ".join(result.failures))

    def test_unparseable_impact_output(self):
        with patch.object(impact_agent.subprocess, "run") as run, \
             redirect_stdout(io.StringIO()) as out:
            run.return_value.returncode = 0
            run.return_value.stdout = self._straddling(200)
            result = impact_agent.analyze_impact(SECRET_ALERT, "diff")
        self._assert_clean(f"{result.error} {result.description} {out.getvalue()}")

    def test_build_check_output(self):
        """`npm run build` can print the file it chokes on, credential included."""
        import sys
        import tempfile
        out = self._straddling(400)
        with tempfile.TemporaryDirectory() as d:
            result = validator._run_check(
                [sys.executable, "-c", f"import sys; sys.stderr.write({out!r}); sys.exit(1)"],
                Path(d), redactor=build_redactor(SECRET_ALERT))
        self.assertFalse(result.passed)
        self._assert_clean(" ".join(result.failures))

    def test_python_syntax_check_output(self):
        """py_compile quotes the offending source line."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "bad.py").write_text(f'KEY = "{SECRET}" +\n')
            result = validator._check_python(["bad.py"], root,
                                             redactor=build_redactor(SECRET_ALERT))
        self.assertFalse(result.passed)
        self.assertNotIn(SECRET[:8] + SECRET[8:12], " ".join(result.failures))

    def test_pipelines_hand_the_build_check_a_redactor(self):
        import inspect

        from pipelines import base, cve
        self.assertIn("redactor=build_redactor(", inspect.getsource(base.FixPipeline.verify))
        self.assertIn("redactor=build_redactor(", inspect.getsource(cve.CvePipeline.verify))

    def test_fix_agent_crash(self):
        task = orchestrator.AlertTask(
            alert_id="orca-abc123", title="t", risk_level="high",
            feature_type="secret", source="app.py:14",
            alert_json=SECRET_ALERT, worktree_path=Path("/tmp/x"))
        with patch.object(orchestrator, "run_in_group") as run, \
             patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", return_value="# i"):
            run.return_value.returncode = 1
            run.return_value.stdout = ""
            run.return_value.stderr = self._straddling(300)
            result = orchestrator._invoke_fix_agent(task, dry_run=False, timeout_sec=5)
        self._assert_clean(result.failure_reason)


class TestRedactor(unittest.TestCase):
    def setUp(self):
        self.r = build_redactor(SECRET_ALERT)

    def test_value_scrubbed_from_prose(self):
        out = self.r(f"The key {SECRET} should be rotated")
        self.assertNotIn(SECRET, out)
        self.assertIn(PLACEHOLDER, out)

    def test_diff_line_scrubbed(self):
        out = self.r(f'-API_KEY = "{SECRET}"\n+API_KEY = os.environ["API_KEY"]')
        self.assertNotIn(SECRET, out)
        self.assertIn("os.environ", out, "the fix side must survive")

    def test_scrub_recurses_into_lists_and_dicts(self):
        out = Redactor([SECRET]).scrub({"steps": [f"rotate {SECRET}"], "n": 3})
        self.assertNotIn(SECRET, str(out))
        self.assertEqual(out["n"], 3, "non-strings pass through unchanged")

    def test_non_string_passes_through(self):
        self.assertIsNone(self.r(None))
        self.assertEqual(self.r(7), 7)


class TestSanityGateRunsForEveryType(unittest.TestCase):
    """A CVE or SAST fix that introduces a credential must fail gate 1 too."""

    def _run(self, feature_type, diff):
        with patch.object(validator, "worktree_diff", return_value=diff):
            return validator.sanity_check({}, Path("/tmp/x"), feature_type=feature_type)

    def test_cve_fix_adding_a_secret_fails(self):
        diff = '+++ b/app.py\n+password = "hunter2hunter2"\n'
        self.assertFalse(self._run("cve", diff).passed)

    def test_sast_fix_adding_a_secret_fails(self):
        diff = "+++ b/app.py\n+token = 'abcdefghijklmnop'\n"
        self.assertFalse(self._run("sast", diff).passed)

    def test_clean_cve_diff_still_passes(self):
        self.assertTrue(self._run("cve", "+++ b/req.txt\n+pillow==11.3.0\n").passed)


class TestModelPromptsAreScrubbed(unittest.TestCase):
    """Neither model subprocess may receive the credential."""

    def test_llm_validate_prompt(self):
        diff = f'-API_KEY = "{SECRET}"\n'
        with patch.object(validator, "worktree_diff", return_value=diff), \
             patch.object(validator.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = '{"verdict": "pass"}'
            validator.llm_validate(SECRET_ALERT, Path("/tmp/x"))
        prompt = run.call_args.kwargs["input"]
        self.assertNotIn(SECRET, prompt)

    def test_impact_prompt(self):
        with patch.object(impact_agent.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = '{"level": "low", "description": "ok"}'
            impact_agent.analyze_impact(SECRET_ALERT, f'-API_KEY = "{SECRET}"\n')
        prompt = run.call_args.kwargs["input"]
        self.assertNotIn(SECRET, prompt)

    def test_model_prose_is_scrubbed_on_the_way_back(self):
        """A model asked to explain the risk will name the credential."""
        raw = f'{{"level": "high", "description": "removes {SECRET}", "concerns": ["{SECRET} is live"]}}'
        with patch.object(impact_agent.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = raw
            result = impact_agent.analyze_impact(SECRET_ALERT, "diff")
        self.assertNotIn(SECRET, result.description)
        self.assertNotIn(SECRET, " ".join(result.concerns))

    def test_validator_reason_is_scrubbed(self):
        raw = f'{{"verdict": "fail", "reason": "still contains {SECRET}"}}'
        with patch.object(validator, "worktree_diff", return_value="d"), \
             patch.object(validator.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = raw
            result = validator.llm_validate(SECRET_ALERT, Path("/tmp/x"))
        self.assertNotIn(SECRET, " ".join(result.failures))

    def test_cve_diff_reaches_the_model_intact(self):
        """The inverse property: gate 2 must still see a non-secret diff."""
        diff = "+pillow==11.3.0\n"
        with patch.object(validator, "worktree_diff", return_value=diff), \
             patch.object(validator.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = '{"verdict": "pass"}'
            validator.llm_validate(CVE_ALERT, Path("/tmp/x"))
        self.assertIn("pillow==11.3.0", run.call_args.kwargs["input"])


class TestPullRequestBody(unittest.TestCase):
    """The PR is the one place the credential survives — so it must say so."""

    def _open_pr(self, alert, feature_type, impact=None, diff_summary="removed the key"):
        task = orchestrator.AlertTask(
            alert_id="orca-abc123", title="Hardcoded secret", risk_level="high",
            feature_type=feature_type, source="app.py:14",
            alert_json=alert, worktree_path=Path("/tmp/x"),
            push_url="https://github.com/o/r.git",
        )
        # files_changed is what _commit_and_pr stages by name, so a task without
        # it is not one the pipeline could ever produce.
        task.fix_result = orchestrator.FixAgentResult(
            success=True, diff_summary=diff_summary, files_changed=["app.py"])
        with patch("orchestrator._run",
                   return_value=("https://github.com/o/r/pull/1", "", 0)) as run:
            orchestrator._commit_and_pr(task, impact=impact, dry_run=False)
        argv = run.call_args_list[-1][0][0]
        return argv[argv.index("--body") + 1]

    def test_secret_pr_carries_the_rotation_warning(self):
        body = self._open_pr(SECRET_ALERT, "secret")
        self.assertIn("does not remediate", body)
        self.assertIn("Rotate the credential first", body)
        self.assertIn("git history", body)

    def test_warning_is_the_first_thing_in_the_body(self):
        body = self._open_pr(SECRET_ALERT, "secret")
        self.assertTrue(body.startswith("> [!WARNING]"), body[:40])

    def test_secret_value_never_reaches_the_body(self):
        impact = impact_agent.ImpactResult(
            level="high", description=f"drops {SECRET}", downtime_risk=False,
            requires_deploy=True, concerns=[f"{SECRET} is live"],
        )
        body = self._open_pr(SECRET_ALERT, "secret", impact=impact,
                             diff_summary=f'removed API_KEY = "{SECRET}"')
        self.assertNotIn(SECRET, body)

    def test_commit_message_is_scrubbed(self):
        """A commit message is permanent, so it gets the same treatment."""
        alert = dict(SECRET_ALERT, code_snippet=[f'KEY = "{SECRET}"'])
        task = orchestrator.AlertTask(
            alert_id="orca-abc123", title=f'leaked {SECRET}', risk_level="high",
            feature_type="secret", source="app.py:14",
            alert_json=alert, worktree_path=Path("/tmp/x"),
            push_url="https://github.com/o/r.git",
        )
        task.fix_result = orchestrator.FixAgentResult(
            success=True, diff_summary="x", files_changed=["app.py"])
        with patch("orchestrator._run",
                   return_value=("https://github.com/o/r/pull/1", "", 0)) as run:
            orchestrator._commit_and_pr(task, impact=None, dry_run=False)
        commit_argv = run.call_args_list[0][0][0]
        self.assertNotIn(SECRET, " ".join(commit_argv))

    def test_cve_pr_has_no_warning(self):
        body = self._open_pr(CVE_ALERT, "cve")
        self.assertNotIn("does not remediate", body)


class TestRotationStep(unittest.TestCase):

    def _impact(self, steps):
        return impact_agent.ImpactResult(
            level="low", description="", downtime_risk=False,
            requires_deploy=False, manual_steps=list(steps),
        )

    def test_rotation_is_prepended_for_secrets(self):
        out = orchestrator._with_rotation_step(self._impact(["Redeploy"]), "secret")
        self.assertIn("Rotate", out.manual_steps[0])
        self.assertEqual(out.manual_steps[1], "Redeploy")

    def test_not_duplicated_when_the_model_already_said_it(self):
        out = orchestrator._with_rotation_step(
            self._impact(["Rotate the credential immediately"]), "secret")
        self.assertEqual(len(out.manual_steps), 1)

    def test_other_types_untouched(self):
        out = orchestrator._with_rotation_step(self._impact(["Redeploy"]), "cve")
        self.assertEqual(out.manual_steps, ["Redeploy"])

    def test_none_impact_is_safe(self):
        self.assertIsNone(orchestrator._with_rotation_step(None, "secret"))


class TestNotificationPayload(unittest.TestCase):
    """One chokepoint feeding the console, the run log and the webhook."""

    def _payload(self, alert, **task_kw):
        task = orchestrator.AlertTask(
            alert_id="orca-abc123", title="t", risk_level="high",
            feature_type="secret", source="app.py:14",
            alert_json=alert, worktree_path=Path("/tmp/x"), **task_kw)
        return orchestrator._notify_payload(task)

    def test_failure_reason_is_scrubbed(self):
        p = self._payload(SECRET_ALERT, failure_reason=f"could not remove {SECRET}")
        self.assertNotIn(SECRET, p.reason)

    def test_impact_fields_are_scrubbed(self):
        task = orchestrator.AlertTask(
            alert_id="a", title="t", risk_level="high", feature_type="secret",
            source="app.py:14", alert_json=SECRET_ALERT, worktree_path=Path("/tmp/x"))
        task.impact = impact_agent.ImpactResult(
            level="high", description="d", downtime_risk=False, requires_deploy=True,
            manual_steps=[f"rotate {SECRET}"], concerns=[f"{SECRET} live"],
            error=f"failed on {SECRET}")
        p = orchestrator._notify_payload(task)
        self.assertNotIn(SECRET, " ".join(p.manual_steps))
        self.assertNotIn(SECRET, " ".join(p.concerns))
        self.assertNotIn(SECRET, p.error_detail)

    def test_none_reason_survives(self):
        self.assertIsNone(self._payload(SECRET_ALERT).reason)


class TestFixAgentReasonAtSource(unittest.TestCase):
    """The fix agent's failure reason feeds the summary, the run log, the webhook
    and the PR body. Scrubbed where it is captured, no later sink can miss it."""

    def _invoke(self, returncode, stdout="", stderr=""):
        task = orchestrator.AlertTask(
            alert_id="orca-abc123", title="t", risk_level="high",
            feature_type="secret", source="app.py:14",
            alert_json=SECRET_ALERT, worktree_path=Path("/tmp/x"))
        with patch.object(orchestrator, "run_in_group") as run, \
             patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", return_value="# i"):
            run.return_value.returncode = returncode
            run.return_value.stdout = stdout
            run.return_value.stderr = stderr
            return orchestrator._invoke_fix_agent(task, dry_run=False, timeout_sec=5)

    def test_reported_reason_is_scrubbed(self):
        raw = f'{{"status": "failed", "reason": "could not remove {SECRET}", "step": "fix_apply"}}'
        result = self._invoke(0, stdout=raw)
        self.assertFalse(result.success)
        self.assertNotIn(SECRET, result.failure_reason)
        self.assertIn(PLACEHOLDER, result.failure_reason)

    def test_agent_summary_is_scrubbed(self):
        raw = (f'{{"status": "success", "files_changed": ["app.py"], '
               f'"diff_summary": "removed {SECRET}", "manual_steps": ["rotate {SECRET}"]}}')
        result = self._invoke(0, stdout=raw)
        self.assertNotIn(SECRET, result.diff_summary)
        self.assertNotIn(SECRET, " ".join(result.manual_steps))

    def test_subprocess_error_is_scrubbed(self):
        result = self._invoke(1, stderr=f"error near API_KEY = \"{SECRET}\"")
        self.assertNotIn(SECRET, result.failure_reason)

    def test_parse_without_a_redactor_still_works(self):
        result = orchestrator._parse_fix_result('{"status": "failed", "reason": "r"}')
        self.assertEqual(result.failure_reason, "r")


class TestRunSummary(unittest.TestCase):
    """The summary prints failure_reason, which can come from anywhere — an
    exception string, a build log, a gate — not only the fix agent."""

    def test_failure_reason_and_title_are_scrubbed(self):
        failed = orchestrator.AlertTask(
            alert_id="orca-abc123", title=f"leaked {SECRET}", risk_level="high",
            feature_type="secret", source="app.py:14", alert_json=SECRET_ALERT,
            state="FAILED", failure_reason=f"local build failed: {SECRET}")
        done = orchestrator.AlertTask(
            alert_id="orca-abc124", title=f"leaked {SECRET}", risk_level="high",
            feature_type="secret", source="app.py:14", alert_json=SECRET_ALERT,
            state="DONE", pr_url="https://github.com/o/r/pull/1")
        out = io.StringIO()
        with redirect_stdout(out):
            orchestrator._print_summary([failed, done], [], [], "o/r", dry_run=False)
        self.assertNotIn(SECRET, out.getvalue())
        self.assertIn("local build failed", out.getvalue())

    def test_plan_title_is_scrubbed(self):
        task = orchestrator.AlertTask(
            alert_id="orca-abc123", title=f"leaked {SECRET}", risk_level="high",
            feature_type="secret", source="app.py:14", alert_json=SECRET_ALERT)
        out = io.StringIO()
        with redirect_stdout(out):
            orchestrator._print_plan([task], [], [], [], "o/r", dry_run=False)
        self.assertNotIn(SECRET, out.getvalue())



def setUpModule():
    _git_sandbox.steady_git_config()


def tearDownModule():
    _git_sandbox.release_git_config()

if __name__ == "__main__":
    unittest.main(verbosity=2)
