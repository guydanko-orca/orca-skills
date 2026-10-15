#!/usr/bin/env python3
"""
Redaction of detected credentials on every path that leaves this process.

A secret fix is the one finding type where the alert hands us the thing we must
not repeat. Removing a hardcoded credential produces a diff whose *removed* line
is the credential, and that diff is then read by two model subprocesses, summarised
into a pull request body, written to the run log and POSTed to a webhook. The
credential is already in the repository — that is the finding — so the PR diff
itself adds no audience the repo did not already have. What the run adds is every
path that leaves the repository's access boundary: Slack, the log file on disk,
two third-party model calls, and the watch notifications a PR body generates.

Those are the paths this module closes. The PR diff is deliberately not one of
them: a commit that removes a line renders that line, and no amount of scrubbing
changes what `git show` prints. Redacting egress is what is achievable; the PR
carrying an explicit "this does not remediate, rotate the credential" warning is
what makes the residue honest (see orchestrator._secret_warning).

What counts as a candidate
--------------------------
Orca gives us no field holding the bare secret value — `_normalize_alert` promotes
`code_snippet`, which is whole source lines, and nothing finer. So candidates are
derived, most specific first:

  1. the assignment value — the quoted literal on the right of `=` or `:`, which
     is the credential itself and the form a model is most likely to quote back
  2. any other quoted literal on the line, for snippets that are not assignments
  3. the whole stripped line, which is what a unified diff actually contains

Keys are never candidates. `API_KEY = "sk-live-…"` yields `sk-live-…`, never
`API_KEY`, because the environment variable name is exactly what the PR has to
tell an operator to set — redacting it would make the remediation instructions
useless.

Only secret findings build a live redactor. For a SAST or CVE alert `code_snippet`
is ordinary vulnerable code with no credential in it, and scrubbing it from a diff
would blind the LLM validation gate to the very lines it has to judge.

When the snippet cannot supply the value
----------------------------------------
Everything above assumes `code_snippet` carries the credential verbatim. If it
arrives masked (`sk-****`), empty, or with no literal a value can be read from,
every candidate is a string that appears nowhere and the redactor matches
nothing — silently. For a secret finding that is the case to fail safe on: the
redactor falls back to the sanity gate's own SECRET_PATTERNS plus a
high-entropy-token heuristic over everything it scrubs, and says so through
`fallback_reason`, which the orchestrator turns into a needs-review reason. A
pattern can miss a credential of an unfamiliar shape, which is why it is flagged
rather than trusted.
"""
import math
import re

from orca_client import _resolve_feature_type

PLACEHOLDER = "[REDACTED-SECRET]"

# Below these lengths a candidate stops identifying the credential and starts
# matching ordinary prose. A 3-character "value" scrubbed everywhere would eat
# words out of the impact description without protecting anything.
_MIN_VALUE_LEN = 6
_MIN_LINE_LEN = 8

# The right-hand side of an assignment: `API_KEY = "sk-live-abc"`, `password: 'hunter2'`.
# Only group 2 (the value) is ever taken — see the module docstring on keys.
_ASSIGNMENT = re.compile(r"""([A-Za-z_][\w.\-]*)\s*[=:]\s*["']([^"']+)["']""")

# Bare quoted literals, for snippets that are not shaped like an assignment
# (a call argument, a YAML scalar, a JSON value).
_QUOTED = re.compile(r"""["']([^"']+)["']""")

# Unquoted `KEY=value`, the .env and Dockerfile `ENV` form, where there are no
# quotes to anchor on. Stops at whitespace so a trailing comment is not absorbed.
_BARE_ASSIGNMENT = re.compile(r"""([A-Za-z_][\w.\-]*)\s*=\s*([^\s"'#]{12,})""")

# Credential shapes, shared with validator.sanity_check, which fails a diff that
# adds a line matching any of them. The `value` group is what the fallback
# redacts; the rest of a match — `API_KEY = "`, `Bearer ` — is left in place,
# since keys are never redacted.
SECRET_PATTERNS = [
    r'(?i)(api_?key|password|secret|token)\s*[=:]\s*["\'](?P<value>[^"\']{8,})["\']',
    r'(?P<value>sk-[A-Za-z0-9]{20,})',
    r'(?i)bearer\s+(?P<value>[A-Za-z0-9+/]{20,})',
]
_COMPILED_PATTERNS = [re.compile(p) for p in SECRET_PATTERNS]

# A masked value: runs of `*` or `•`, an x-run, or a redaction marker. A
# candidate containing one of these matches nothing in real text.
_MASKED = re.compile(r"\*{3,}|•{3,}|(?i:x{6,})|(?i:redacted|masked)")

# A run long enough to be a key and drawn from the alphabets keys use. Shorter
# than 20 it starts matching words; a fence tag (`/untrusted-` plus an 8-hex
# nonce) is 19, so it can never be taken for one.
_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
_MIN_TOKEN_ENTROPY = 3.8   # bits per character; identifiers and words sit well below

FALLBACK_REASON = (
    "Orca's code_snippet for this secret finding did not contain a usable "
    "credential value (masked, empty or unparseable), so outbound text was "
    "redacted by secret patterns and an entropy heuristic instead of by exact "
    "value. A credential matching neither may not have been redacted from the "
    "model prompts, the PR body or the notifications.")


def _snippet_lines(alert: dict) -> list[str]:
    """The alert's code_snippet as a list of lines, however Orca shaped it."""
    raw = alert.get("code_snippet") or []
    lines = [str(item) for item in raw] if isinstance(raw, list) else str(raw).splitlines()
    return [ln.strip() for ln in lines if ln and ln.strip()]


def _candidates(alert: dict) -> tuple[list[str], bool]:
    """Strings that must not appear in anything this run emits, and whether any
    of them is a value rather than only a whole line.

    Ordered longest first so that replacement cannot leave a fragment behind: if
    the whole line and the value inside it are both candidates, scrubbing the
    line first means the value's own pass finds nothing left to do, whereas the
    reverse order would leave the line's surrounding text intact and correct.

    Masked strings are dropped: they cannot match anything real, and keeping one
    made the redactor look armed while it scrubbed nothing.
    """
    values: set[str] = set()
    lines: set[str] = set()

    for line in _snippet_lines(alert):
        for _key, value in _ASSIGNMENT.findall(line):
            if len(value) >= _MIN_VALUE_LEN:
                values.add(value)
        for _key, value in _BARE_ASSIGNMENT.findall(line):
            values.add(value)
        for value in _QUOTED.findall(line):
            if len(value) >= _MIN_VALUE_LEN:
                values.add(value)
        if len(line) >= _MIN_LINE_LEN:
            lines.add(line)

    usable_values = {v for v in values if not _MASKED.search(v)}
    found = usable_values | {ln for ln in lines if not _MASKED.search(ln)}
    return sorted(found, key=len, reverse=True), bool(usable_values)


def _looks_masked(alert: dict) -> bool:
    return any(_MASKED.search(line) for line in _snippet_lines(alert))


def _entropy(token: str) -> float:
    counts = {c: token.count(c) for c in set(token)}
    return -sum(n / len(token) * math.log2(n / len(token)) for n in counts.values())


def _looks_random(token: str) -> bool:
    return (any(c.isdigit() for c in token) and any(c.isalpha() for c in token)
            and _entropy(token) >= _MIN_TOKEN_ENTROPY)


def _scrub_patterns(text: str) -> str:
    """Redact by shape: SECRET_PATTERNS' value groups, then random-looking tokens."""
    def value_only(m):
        start, end = m.span("value")
        return m.string[m.start():start] + PLACEHOLDER + m.string[end:m.end()]

    for pattern in _COMPILED_PATTERNS:
        text = pattern.sub(value_only, text)
    return _TOKEN.sub(lambda m: PLACEHOLDER if _looks_random(m.group()) else m.group(),
                      text)


class Redactor:
    """Callable that replaces every known credential fragment with PLACEHOLDER.

    An instance with no candidates is falsy and returns its input untouched, so
    callers can build one unconditionally and skip the `if feature_type ==`
    dance at each call site.
    """

    def __init__(self, candidates: list[str] | None = None,
                 fallback_reason: str | None = None):
        self.candidates = candidates or []
        # Set when the alert could not supply the credential itself. Pattern
        # redaction then runs on everything, and the reason is what the PR says.
        self.fallback_reason = fallback_reason

    def __bool__(self) -> bool:
        return bool(self.candidates or self.fallback_reason)

    def __call__(self, text):
        """Scrub a string. Non-strings pass through, so this is safe on Optionals."""
        if not self or not text or not isinstance(text, str):
            return text
        for candidate in self.candidates:
            if candidate in text:
                text = text.replace(candidate, PLACEHOLDER)
        if self.fallback_reason:
            text = _scrub_patterns(text)
        return text

    def scrub(self, value):
        """Scrub recursively through lists, tuples and dicts of strings.

        Notification payloads carry `manual_steps` and `concerns` as lists, and
        the impact agent's parsed JSON arrives as a dict, so a string-only
        redactor would quietly miss both.
        """
        if isinstance(value, str):
            return self(value)
        if isinstance(value, list):
            return [self.scrub(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.scrub(item) for item in value)
        if isinstance(value, dict):
            return {k: self.scrub(v) for k, v in value.items()}
        return value


_NULL_REDACTOR = Redactor()


def build_redactor(alert: dict | None) -> Redactor:
    """The redactor for one alert. Always returns an instance, never None.

    Non-secret findings get the no-op redactor: there is no known credential to
    scrub, and blanking their code_snippet out of a diff would break the gates
    that have to read it. A secret finding always gets a live one — by exact
    value when the snippet has one, by pattern when it does not.
    """
    if not alert or not isinstance(alert, dict):
        return _NULL_REDACTOR
    if _resolve_feature_type(alert) != "secret":
        return _NULL_REDACTOR
    candidates, has_value = _candidates(alert)
    if has_value and not _looks_masked(alert):
        return Redactor(candidates)
    return Redactor(candidates, fallback_reason=FALLBACK_REASON)
