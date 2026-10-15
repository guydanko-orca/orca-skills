#!/usr/bin/env python3
"""
The per-finding-type seam in the fix pipeline.

`_run_pipeline` used to hold every type's quirks inline, with the only
per-type knobs being two module-level dicts (`TIMEOUTS`, `_DIFF_LIMITS`) far
away from the code that cared. A pipeline object collects them in one place and
adds two hooks around the fix agent:

  prepare()  before the agent runs — work out anything the agent should be told
             rather than left to decide
  verify()   after the agent runs — check the thing that actually matters for
             this type, which is not the same check for a manifest bump as for
             a rewritten SQL query

Specializing a type means adding a pipeline, not editing the orchestrator.
"""
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from validator import ValidationResult, local_build_check


@dataclass
class FixPlan:
    """What a specialist worked out before the fix agent was invoked.

    render_directive is appended to the fix prompt, so a pipeline can turn
    "figure out what to do" into "do this". It is a function of the prompt's
    nonce rather than a finished string because what it states — a package
    name, a manifest path, a version — comes from the repository and the
    advisory feeds, so those values have to be fenced with the nonce of the
    prompt they land in, which does not exist until the agent is invoked.
    metadata travels on to impact analysis and the PR body, which is how a
    decision made here becomes reviewable later.
    """
    summary: str = ""
    render_directive: Callable[[str], str] | None = field(default=None, repr=False,
                                                         compare=False)
    metadata: dict = field(default_factory=dict)
    needs_review: bool = False
    error: str | None = None

    def directive(self, nonce: str) -> str:
        """The directive for one fix prompt, or "" when there is none."""
        return self.render_directive(nonce) if self.render_directive else ""

    @property
    def prepared(self) -> bool:
        return self.error is None and bool(self.render_directive or self.metadata)


class FixPipeline:
    """Default behaviour: exactly what the pipeline did before this existed.

    Subclasses override `prepare` and `verify`. The base class is not abstract on
    purpose — sast, iac and secret genuinely have nothing to prepare yet, and a
    no-op base keeps them on the old path byte for byte until someone
    specializes them.
    """

    feature_type = "generic"

    def __init__(self, feature_type: str = "generic", timeout_sec: int = 180,
                 diff_limit: int = 50):
        self.feature_type = feature_type
        self.timeout_sec = timeout_sec
        self.diff_limit = diff_limit

    # The tools a fix agent of this type gets. No Bash: sast, iac and secret
    # reach for a shell exactly once, to `git checkout -- <file>` after a bad
    # edit, and orchestrator._revert already does that more thoroughly on every
    # failure path. A type that genuinely needs one says so by overriding.
    AGENT_TOOLS = ["Read", "Edit", "Write"]

    def agent_tools(self, plan: FixPlan | None = None) -> list[str]:
        """Tool names for `--tools`, which removes the rest from the model's context."""
        return list(self.AGENT_TOOLS)

    def bash_allowlist(self, plan: FixPlan | None = None) -> list[str]:
        """Permission patterns for `--allowedTools`, e.g. `Bash(go mod tidy:*)`.

        Empty means the agent has no shell at all. Non-empty entries are matched
        per command segment — a chained `allowed ; something-else` does not pass.
        """
        return []

    def prepare(self, task, worktree_path: Path) -> FixPlan:
        """Nothing to work out ahead of time."""
        return FixPlan()

    def verify(self, task, worktree_path: Path,
               plan: FixPlan | None = None) -> ValidationResult:
        """Language-appropriate build check — the pre-existing Phase 3."""
        alert = task.alert_json or {}
        files = task.fix_result.files_changed if task.fix_result else []
        return local_build_check(
            files, worktree_path,
            source_file=alert.get("file_path") or alert.get("source", ""),
        )
