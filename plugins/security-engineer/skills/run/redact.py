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
random-token heuristic (per-alphabet entropy floors, names and paths excluded)
over everything it scrubs, and says so through
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
# since keys are never redacted. No pattern may cross a line break: the fallback
# runs over whole fenced prompts, and a value class that admits a newline turned
# one unclosed quote in a diff into a match running to the next quote anywhere
# after it — the fence's closing tag and the instructions included.
SECRET_PATTERNS = [
    r'(?i)(api_?key|password|secret|token)[ \t]*[=:][ \t]*["\'](?P<value>[^"\'\r\n]{8,})["\']',
    r'(?P<value>sk-[A-Za-z0-9]{20,})',
    r'(?i)bearer[ \t]+(?P<value>[A-Za-z0-9+/]{20,})',
]
_COMPILED_PATTERNS = [re.compile(p) for p in SECRET_PATTERNS]

# A masked line: star or bullet runs, or a redaction marker. Kept narrow, since
# a whole source line legitimately holds `...`, `<T>` or a `----` banner.
_MASKED = re.compile(r"\*{3,}|•{3,}|(?i:redacted|masked)")
# A masked value is judged more broadly — it is meant to be the credential, so
# any of these means it is not: a run of one punctuation character (`....`,
# `####`), an ellipsis, an x-run, a marker word, or a whole-value placeholder
# such as `<hidden-value>`. A candidate like this matches nothing in real text.
_MASKED_VALUE = re.compile(
    r"([^A-Za-z0-9\s])\1{3,}|\*{3,}|•{3,}|\.{3}|…|(?i:x{4,})"
    r"|(?i:redacted|masked|hidden)|^<[^<>]*>$")

# A run long enough to be a key and drawn from the alphabets keys use. Shorter
# than 20 it starts matching words; a fence tag (`/untrusted-` plus an 8-hex
# nonce) is 19, so it can never be taken for one.
_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")

# A token is judged by its separator-free parts, so `fix/orca-12345678-abcdef`
# is four short words, not one 24-character key, while the random tail of
# `sk-live-<random>` is still judged on its own.
_PART_SEP = re.compile(r"[/._\-@]")
_MIN_PART = 16
# Floors are per alphabet, because the ceiling is: hex cannot exceed 4 bits per
# character, and a random 20-character string cannot exceed log2(20) ≈ 4.3
# whatever its alphabet. A single floor that suits base64 misses most hex keys.
_HEX_MIN_ENTROPY = 3.0
_MIXED_ENTROPY_MARGIN = 0.9  # below log2(length)
_DIGEST_LENGTHS = (40, 64)   # git SHA-1 / SHA-256 and the digests shaped like them
_SRI = re.compile(r"sha(?:1|256|384|512)-")

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
    made the redactor look armed while it scrubbed nothing. A value only counts
    as found when it is shaped like a credential — a SECRET_PATTERNS value or a
    random-looking token. Anything else is still scrubbed exactly, but cannot be
    trusted to be the credential, so the caller falls back to patterns as well.
    """
    values: set[str] = set()
    lines: set[str] = set()
    shaped: set[str] = set()

    for line in _snippet_lines(alert):
        for pattern in _COMPILED_PATTERNS:
            shaped.update(m.group("value") for m in pattern.finditer(line))
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

    unmasked = {v for v in values if not _MASKED_VALUE.search(v)}
    confirmed = {v for v in unmasked if v in shaped or _looks_random(v)}
    found = unmasked | {ln for ln in lines if not _MASKED.search(ln)}
    return sorted(found, key=len, reverse=True), bool(confirmed)


def _looks_masked(alert: dict) -> bool:
    lines = _snippet_lines(alert)
    if any(_MASKED.search(line) for line in lines):
        return True
    return any(_MASKED_VALUE.search(value)
               for line in lines
               for value in [*(v for _k, v in _ASSIGNMENT.findall(line)),
                             *_QUOTED.findall(line)])


def _entropy(token: str) -> float:
    counts = {c: token.count(c) for c in set(token)}
    return -sum(n / len(token) * math.log2(n / len(token)) for n in counts.values())


def _part_looks_random(part: str) -> bool:
    if len(part) < _MIN_PART:
        return False
    if re.fullmatch(r"[0-9a-fA-F]+", part):
        if len(part) in _DIGEST_LENGTHS:
            return False
        return (bool(re.search(r"[0-9]", part)) and bool(re.search(r"[a-fA-F]", part))
                and _entropy(part) >= _HEX_MIN_ENTROPY)
    classes = sum(bool(re.search(c, part)) for c in (r"[a-z]", r"[A-Z]", r"[0-9]"))
    if classes < 2:
        return False
    # camelCase and PascalCase names are mostly runs of lowercase letters; a
    # random string over 62+ symbols almost never is.
    if sum(len(run) for run in re.findall(r"[a-z]{3,}", part)) >= len(part) / 2:
        return False
    return _entropy(part) >= math.log2(len(part)) - _MIXED_ENTROPY_MARGIN


def _looks_random(token: str, keep: frozenset = frozenset()) -> bool:
    if _SRI.match(token):
        return False
    return any(_part_looks_random(part) for part in _PART_SEP.split(token)
               if part not in keep)


def _scrub_patterns(text: str, keep: frozenset = frozenset()) -> str:
    """Redact by shape: SECRET_PATTERNS' value groups, then random-looking tokens.

    keep: path parts never to treat as keys — the alert's own file path, which
          gate 2 and the PR body have to name, however it is prefixed.
    """
    def value_only(m):
        start, end = m.span("value")
        return m.string[m.start():start] + PLACEHOLDER + m.string[end:m.end()]

    for pattern in _COMPILED_PATTERNS:
        text = pattern.sub(value_only, text)
    return _TOKEN.sub(lambda m: PLACEHOLDER if _looks_random(m.group(), keep) else m.group(),
                      text)


def _path_tokens(alert: dict) -> frozenset:
    paths = " ".join(str(alert.get(k) or "") for k in ("file_path", "source"))
    return frozenset(part for token in _TOKEN.findall(paths)
                     for part in _PART_SEP.split(token))


class Redactor:
    """Callable that replaces every known credential fragment with PLACEHOLDER.

    An instance with no candidates is falsy and returns its input untouched, so
    callers can build one unconditionally and skip the `if feature_type ==`
    dance at each call site.
    """

    def __init__(self, candidates: list[str] | None = None,
                 fallback_reason: str | None = None, keep: frozenset = frozenset()):
        self.candidates = candidates or []
        # Set when the alert could not supply the credential itself. Pattern
        # redaction then runs on everything, and the reason is what the PR says.
        self.fallback_reason = fallback_reason
        self.keep = keep

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
            text = _scrub_patterns(text, self.keep)
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
    return Redactor(candidates, fallback_reason=FALLBACK_REASON, keep=_path_tokens(alert))
