#!/usr/bin/env python3
"""The environment a model subprocess is allowed to see.

There was no `env=` anywhere in this plugin, so every `claude -p` call inherited
the orchestrator's environment: ORCA_API_TOKEN, NOTIFY_WEBHOOK_URL and whatever
credentials `gh` was authenticated with. A process whose whole job is reading
repository content — content an attacker can write — has no use for any of them,
and all four call sites are covered here rather than one.

The local build checks get the same allowlist through build_env(), minus Claude's
own credentials: `npm run build` executes a script the tenant wrote, which is the
untrusted party in person, and it has no more use for ANTHROPIC_API_KEY than for
ORCA_API_TOKEN.

The orchestrator's own `gh` and `git` subprocesses keep their environment. They
need those credentials, and they are not the untrusted party — but the hooks a
repository can attach to them are, so they run through HOOKLESS_GIT.
"""
import atexit
import contextlib
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time

from config import load_config

# An allowlist of names, never a pattern: NPM_TOKEN would sail through any
# prefix rule written for npm. Values are read from the real environment at call
# time, so nothing in this file holds a secret.
_ALLOW = frozenset({
    # process and shell basics. HOME stays real even for build checks: a
    # throwaway one hides no file from code running as this user, and it
    # breaks toolchain caches — see HARNESS.md.
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "LANG", "LC_ALL",
    "LC_CTYPE", "TERM", "TZ",
    # TLS trust and proxies — without these a corporate network breaks the call
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "no_proxy",
    # Claude's own auth and routing. ANTHROPIC_API_KEY is a credential and is
    # here on purpose: it is the one the subprocess is entitled to.
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
    "ANTHROPIC_MODEL", "ANTHROPIC_SMALL_FAST_MODEL",
    "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX",
    # Toolchain caches, so the lockfile regens do not redownload the world.
    # Caches only — GOPROXY, GOPRIVATE, NPM_CONFIG_REGISTRY and PIP_INDEX_URL
    # are excluded because each can carry credentials inside a URL. A private
    # registry adds them through fix_agent.extra_env, deliberately.
    "GOPATH", "GOMODCACHE", "GOCACHE", "GOFLAGS",
    "CARGO_HOME", "RUSTUP_HOME",
    "npm_config_cache", "NPM_CONFIG_CACHE",
    "BUNDLE_PATH", "GEM_HOME", "GEM_PATH",
    "DOTNET_CLI_HOME", "NUGET_PACKAGES",
    "JAVA_HOME", "M2_HOME", "PIP_CACHE_DIR",
    "GOTOOLCHAIN", "XDG_CACHE_HOME", "TF_PLUGIN_CACHE_DIR", "TF_DATA_DIR",
})

# Allowed for the model subprocess, which needs them to reach Claude; withheld
# from build checks, which run repository code and need none of them. A prefix,
# so one added through extra_env is withheld too.
_MODEL_ONLY_PREFIXES = ("ANTHROPIC_", "CLAUDE_CODE_")

_SCRUB = "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"

# Names fix_agent.extra_env may never add back. The literal four are the ones
# this change exists to withhold; the pattern catches the shape of the rest, so
# an operator adding AWS_REGION for Bedrock cannot also add AWS_SECRET_ACCESS_KEY
# without noticing. It does not apply to _ALLOW above, which is
# reviewed here rather than configured.
_NEVER = {"ORCA_API_TOKEN", "ORCA_AUTH_TOKEN", "NOTIFY_WEBHOOK_URL",
              "GH_TOKEN", "GITHUB_TOKEN"}
# Every hook event in githooks(5) as of git 2.56. Config-defined hooks
# (`hook.<name>.command`, git >= 2.54) do not live in core.hooksPath, so each
# event is switched off by name. Older git has no config hooks and ignores the
# unknown keys — checked against Apple git 2.50.
_HOOK_EVENTS = (
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit",
    "pre-merge-commit", "prepare-commit-msg", "commit-msg", "post-commit",
    "pre-rebase", "post-checkout", "post-merge", "pre-push", "pre-receive",
    "update", "proc-receive", "post-receive", "post-update",
    "reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite",
    "sendemail-validate", "fsmonitor-watchman", "p4-changelist",
    "p4-prepare-changelist", "p4-post-changelist", "p4-pre-submit",
    "post-index-change",
)

# Every git command the plugin runs where a hook can fire. `git commit` and
# `git push` run the repository's hooks — husky, pre-commit, pre-push — with the
# orchestrator's environment, which holds the Orca token and whatever `gh` is
# authenticated with. In single-repo mode those are the operator's own hooks,
# live; and a lockfile regen that executes repository code (`bundle lock`
# evaluates the Gemfile) can rewrite the shared .git/config mid-run. A
# command-line -c outranks every config file, so this holds whatever the clone's
# config says about hooks and fsmonitor; other command-running keys
# (credential.helper, core.sshCommand) are caught by the orchestrator's config
# drift check instead. The cost: repo-local hooks no longer run on bot commits,
# so anything they enforce is left to CI and the Orca check.
HOOKLESS_GIT = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                *(arg for event in _HOOK_EVENTS
                  for arg in ("-c", f"hook.{event}.enabled=false"))]

# KEY, AUTH and DSN: OPENAI_API_KEY, BASIC_AUTH_HEADER and SENTRY_DSN carry a
# credential under none of the other words. None of the documented extra_env
# uses (AWS_REGION, AWS_PROFILE, GOPROXY, GOPRIVATE, NPM_CONFIG_REGISTRY,
# PIP_INDEX_URL) contains one.
_NEVER_SHAPE = re.compile(
    r"TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|COOKIE|SESSION|KEY|AUTH|DSN",
    re.IGNORECASE)


def agent_env(extra: list | None = None) -> dict:
    """The environment for a model subprocess: allowlisted names only.

    extra defaults to fix_agent.extra_env from config; tests pass it directly.
    """
    if extra is None:
        extra = load_config().fix_agent.extra_env
    allowed = set(_ALLOW)
    for name in (extra or []):
        name = str(name).strip()
        if not name:
            continue
        if name in _NEVER or _NEVER_SHAPE.search(name):
            print(f"[WARN] ignoring fix_agent.extra_env entry {name!r}: "
                  f"credential-shaped names cannot be added to the agent "
                  f"environment", flush=True)
            continue
        allowed.add(name)
    env = {k: v for k, v in os.environ.items() if k in allowed}
    # The fix agent's Bash runs lockfile regens — `bundle lock` evaluates the
    # Gemfile, `dotnet restore` runs MSBuild targets — and inherits claude's own
    # environment, which must hold Claude's credentials for the API call. This
    # makes claude strip credential-shaped variables from every subprocess it
    # starts while keeping them for itself. Forced, so an inherited "0" cannot
    # turn it off. Verified against claude 2.1.299 with a canary variable.
    env[_SCRUB] = "1"
    return env


def build_env(extra: list | None = None) -> dict:
    """The environment for a build or syntax check run inside the cloned tree.

    agent_env() without Claude's credentials. fix_agent.extra_env still applies,
    so a private registry an operator opted into reaches the build that needs it.
    """
    return {k: v for k, v in agent_env(extra).items()
            if not k.startswith(_MODEL_ONLY_PREFIXES)}


# ---------------------------------------------------------------------------
# The git configuration every plugin git call reads
# ---------------------------------------------------------------------------

# Where a child process (run_agent.py) finds the snapshot its parent made, so a
# run reads the operator's global config exactly once.
GIT_SNAPSHOT_ENV = "SECURITY_ENGINEER_GIT_CONFIG"

_snapshot_path: str | None = None
_snapshot_lock = threading.Lock()

# GIT_CONFIG_GLOBAL, the override everything here rests on, arrived in git 2.32.
_MIN_GIT = (2, 32)

# Their targets are inlined by --includes when the snapshot is taken. Kept, git
# would follow them again to live files under HOME — which build code can write.
_INCLUDE_KEY = re.compile(r"^(include|includeif\..*)\.path$", re.IGNORECASE)


def _git_version() -> tuple:
    out = subprocess.run(["git", "--version"], capture_output=True, text=True).stdout
    match = re.search(r"(\d+)\.(\d+)", out)
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def _scope_entries(scope: str, cwd: str) -> list[tuple[str, str]]:
    r = subprocess.run(["git", "config", scope, "--list", "-z", "--includes"],
                       cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        # No ~/.gitconfig at all is an empty global config, not an error.
        if "No such file or directory" in r.stderr:
            return []
        raise RuntimeError(f"could not read the {scope[2:]} git config: "
                           f"{r.stderr.strip()[:200]}")
    entries = []
    for raw in r.stdout.split("\0"):
        if not raw:
            continue
        key, newline, value = raw.partition("\n")
        if _INCLUDE_KEY.match(key):
            continue
        # A valueless key is a boolean true.
        entries.append((key, value if newline else "true"))
    return entries


def _write_snapshot() -> str:
    if _git_version() < _MIN_GIT:
        raise RuntimeError("git >= 2.32 is required: the plugin isolates every git "
                           "call from ~/.gitconfig with GIT_CONFIG_GLOBAL")
    directory = tempfile.mkdtemp(prefix="security-engineer-git-")   # 0700
    atexit.register(shutil.rmtree, directory, ignore_errors=True)
    path = os.path.join(directory, "gitconfig")
    os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
    # Read from a directory with no repository, so no repo config is mixed in;
    # system first, so a global value later in the file wins as it does in git.
    no_system = os.environ.get("GIT_CONFIG_NOSYSTEM", "").lower() in ("1", "true", "yes")
    system = [] if no_system else _scope_entries("--system", directory)
    for key, value in (*system, *_scope_entries("--global", directory)):
        subprocess.run(["git", "config", "--file", path, "--add", key, value],
                       cwd=directory, check=True, capture_output=True)
    return path


def git_config_snapshot() -> str:
    """The plugin's private copy of the operator's system + global git config.

    Taken once, at the first call — orchestrator.main() makes that the start of
    the run — and inherited by child processes through GIT_SNAPSHOT_ENV. Every
    plugin git call reads it through GIT_CONFIG_GLOBAL with system config off,
    so a build check that rewrites ~/.gitconfig mid-run changes nothing the
    plugin's git sees, for this alert or for a repository cloned later.
    """
    global _snapshot_path
    with _snapshot_lock:
        if _snapshot_path is None:
            inherited = os.environ.get(GIT_SNAPSHOT_ENV)
            _snapshot_path = (inherited if inherited and os.path.isfile(inherited)
                              else _write_snapshot())
        return _snapshot_path


def _reset_git_config_snapshot() -> None:
    """Tests only: forget the snapshot so the next call takes a fresh one."""
    global _snapshot_path
    with _snapshot_lock:
        _snapshot_path = None


def isolate_git_config(env: dict) -> dict:
    """Point a git (or gh) environment at the snapshot, and nothing else."""
    for name in [k for k in env if k.startswith("GIT_CONFIG")]:
        del env[name]
    env["GIT_CONFIG_GLOBAL"] = git_config_snapshot()
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env[GIT_SNAPSHOT_ENV] = env["GIT_CONFIG_GLOBAL"]
    return env


def run_env() -> dict:
    """The full environment, isolated: for run_agent.py, which calls the Orca API."""
    return isolate_git_config(dict(os.environ))


# Not needed by git or gh: the Orca API token, the webhook, Claude's own auth.
_NOT_FOR_GIT = {"ORCA_API_TOKEN", "ORCA_AUTH_TOKEN", "NOTIFY_WEBHOOK_URL"}


def credentialed_env() -> dict:
    """For the calls that need GitHub credentials — push, commit (signing), gh."""
    env = {k: v for k, v in run_env().items()
           if k not in _NOT_FOR_GIT and not k.startswith(_MODEL_ONLY_PREFIXES)}
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def git_env() -> dict:
    """For every git call that needs no credentials: the build-check allowlist.

    After repository code has run, a clone's config can name commands git runs
    on a local operation — a clean filter on `git add`, a textconv on `git
    diff`. Whatever runs that way gets this environment: no GitHub, Orca, Claude
    or webhook credential. It still runs as the operator with the real HOME, so
    it is not a sandbox — the config drift check, made before these calls, is
    what keeps a planted command from running at all.
    """
    env = isolate_git_config(build_env())
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


# Local git calls — add, diff, status, commit, reset, checkout, worktree,
# branch — need no network and no credential, so every way config can make them
# reach for one is switched off: no credential helper, no askpass, an ssh that
# cannot run, no transport at all, no global attributes file, no external diff.
SAFE_GIT = [*HOOKLESS_GIT,
            "-c", "credential.helper=", "-c", "core.askPass=",
            "-c", "core.sshCommand=false", "-c", "protocol.allow=never",
            "-c", "core.attributesFile=/dev/null", "-c", "diff.external="]

_CREDENTIAL_HELPER = re.compile(r"^credential(\..+)?\.helper$")


def _snapshot_values(pattern) -> list[tuple[str, str]]:
    r = subprocess.run(["git", "config", "--file", git_config_snapshot(), "--list", "-z"],
                       capture_output=True, text=True, check=True)
    entries = [raw.partition("\n") for raw in r.stdout.split("\0") if raw]
    return [(key, value) for key, _, value in entries if pattern.match(key)]


def push_git() -> list[str]:
    """The git prefix for a push: the operator's own credential and ssh setup,
    from the snapshot, and nothing a clone's config added.

    `credential.helper=` empties the helper list — every helper, URL-scoped or
    not, from every file read before the command line — and the snapshot's
    helpers are then added back in their own order. Verified with
    `git credential fill`: a helper planted in the repository config, generic or
    URL-scoped, does not run. url.*.insteadOf cannot be reset this way, because
    its keys are named by URL; a planted one is caught by the drift check made
    immediately before the push.
    """
    prefix = [*HOOKLESS_GIT, "-c", "credential.helper="]
    for key, value in _snapshot_values(_CREDENTIAL_HELPER):
        prefix += ["-c", f"{key}={value}"]
    ssh = [v for _k, v in _snapshot_values(re.compile(r"^core\.sshcommand$"))]
    askpass = [v for _k, v in _snapshot_values(re.compile(r"^core\.askpass$"))]
    prefix += ["-c", f"core.sshCommand={ssh[-1] if ssh else 'ssh'}",
               "-c", f"core.askPass={askpass[-1] if askpass else ''}",
               "-c", "http.extraHeader=",
               "-c", "core.attributesFile=/dev/null", "-c", "diff.external="]
    return prefix


def neutral_dir() -> str:
    """A directory that is not a repository, for gh to run in.

    gh inspects the git repository in its working directory — remotes, branch,
    uncommitted changes — with our credentials and none of the overrides above.
    Every gh call names its repository explicitly and runs here instead.
    """
    return os.path.dirname(git_config_snapshot())


# ---------------------------------------------------------------------------
# Repository code runs in a process group that does not outlive it
# ---------------------------------------------------------------------------

def _kill_group(pgid: int) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, signal.SIGKILL)


def _exited(proc) -> bool:
    """Has the leader exited? Without reaping it where the platform allows."""
    if hasattr(os, "waitid"):
        return os.waitid(os.P_PID, proc.pid,
                         os.WEXITED | os.WNOWAIT | os.WNOHANG) is not None
    # CPython on macOS before 3.13 has no os.waitid. Reaping here frees the pid,
    # so the kill that follows has a window of microseconds in which an
    # unrelated process could have taken that pid and made it a group id.
    return proc.poll() is not None


def run_in_group(cmd, *, input=None, timeout=None, cwd=None, env=None
                 ) -> subprocess.CompletedProcess:
    """subprocess.run for the processes that run repository code — the fix
    agent, whose Bash runs lockfile regens, and the build checks.

    The command gets its own session and process group, and the whole group is
    killed when the command exits or times out. Without that, a child it left
    running in the background could rewrite the clone's git config after the
    last drift check and before the push. Where os.waitid exists the group is
    killed while the leader is still an unreaped zombie (WNOWAIT), so its id
    cannot have been reused by an unrelated process; see _exited for where it
    does not. A child that calls setsid() itself leaves the group and is not
    caught.
    """
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE if input is not None else
                            subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, cwd=cwd, env=env,
                            start_new_session=True)
    out: list[str] = []
    err: list[str] = []
    readers = [threading.Thread(target=lambda s=stream, sink=sink: sink.append(s.read()),
                                daemon=True)
               for stream, sink in ((proc.stdout, out), (proc.stderr, err))]
    for reader in readers:
        reader.start()
    if input is not None:
        try:
            proc.stdin.write(input)
        except BrokenPipeError:
            pass
        finally:
            proc.stdin.close()
    deadline = None if timeout is None else time.monotonic() + timeout
    timed_out = False
    while not _exited(proc):
        if deadline is not None and time.monotonic() >= deadline:
            timed_out = True
            break
        time.sleep(0.05)
    _kill_group(proc.pid)
    proc.wait()
    # Bounded: a child that left the group with setsid() and kept the pipe open
    # would otherwise hold the alert forever. Its late output is dropped.
    for reader in readers:
        reader.join(5)
    stdout, stderr = "".join(out), "".join(err)
    if timed_out:
        raise subprocess.TimeoutExpired(cmd, timeout, output=stdout, stderr=stderr)
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
