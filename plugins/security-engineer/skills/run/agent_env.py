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
import os
import re

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
