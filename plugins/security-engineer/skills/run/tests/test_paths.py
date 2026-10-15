#!/usr/bin/env python3
"""Tests for alert-derived path handling.

Every path here is built from a value someone else supplied — an alert_id from
the API, a `source` or `manifest_path` from a finding, a file list a model
reported — and one of them is an argument to shutil.rmtree.

Run with: python3 tests/test_paths.py
"""
import os
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from unittest.mock import patch

_DIR = Path(__file__).parent
sys.path.insert(0, str(_DIR.parent))
sys.path.insert(0, str(_DIR.parent.parent / "lib"))

sys.path.insert(0, str(_DIR))                        # tests/
import _git_sandbox  # noqa: F401  (hermetic git config snapshot)
import agent_env
import orchestrator
import package_identity
import validator
from orca_client import Repository
from orchestrator import AlertTask, FixAgentResult, _declared_paths, _worktree_path
from paths import WORKTREE_PREFIX, assert_disposable, resolve_within, safe_name


class TestSafeName(unittest.TestCase):
    """alert_id names a directory that gets deleted, so it is an allowlist."""

    CASES = [
        ("a slash becomes a dash, as alert_branch_name already did",
         "orca-ab/cd", "orca-ab-cd"),
        ("traversal cannot survive", "../../etc", "etc"),
        ("a bare parent directory cannot survive", "..", "unnamed"),
        ("the current directory cannot survive", ".", "unnamed"),
        ("empty is never returned", "", "unnamed"),
        ("shell metacharacters are dropped", "a;rm -rf /;b", "a-rm--rf---b"),
        ("newlines are dropped", "a\nb", "a-b"),
        ("ordinary ids are untouched", "orca-abc123", "orca-abc123"),
    ]

    def test_cases(self):
        for desc, raw, expected in self.CASES:
            with self.subTest(desc):
                self.assertEqual(safe_name(raw), expected, desc)

    def test_worktree_path_sanitizes_both_halves(self):
        repo = Repository(name="owner/repo", url="https://github.com/owner/repo")
        path = _worktree_path("../../../etc/passwd", repo)
        self.assertEqual(path.parent, Path("/tmp"))
        self.assertTrue(path.name.startswith(f"{WORKTREE_PREFIX}owner-repo-"))
        self.assertNotIn("..", str(path))


class TestResolveWithin(unittest.TestCase):
    """`Path.__truediv__` does not normalise, so the join has to be checked."""

    # Results are resolved, so they are compared against the resolved root:
    # on macOS /tmp is a symlink to /private/tmp.
    ROOT = "/tmp/orca-fix-owner-repo-1"

    def test_ordinary_relative_path_resolves(self):
        self.assertEqual(resolve_within(self.ROOT, "src/app.py"),
                         Path(self.ROOT).resolve() / "src/app.py")

    def test_traversal_is_refused(self):
        self.assertIsNone(resolve_within(self.ROOT, "../../etc/passwd"))

    def test_traversal_that_returns_inside_is_allowed(self):
        """`a/../b` never leaves, and refusing it would fail honest alerts."""
        self.assertEqual(resolve_within(self.ROOT, "a/../b.py"),
                         Path(self.ROOT).resolve() / "b.py")

    def test_absolute_path_is_refused(self):
        self.assertIsNone(resolve_within(self.ROOT, "/etc/passwd"))

    def test_symlink_out_of_the_tree_is_refused(self):
        """A cloned repository can contain a symlink; resolving catches it."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "worktree"
            (root / "sub").mkdir(parents=True)
            outside = Path(tmp) / "outside"
            outside.mkdir()
            (root / "sub" / "link").symlink_to(outside)
            self.assertIsNone(resolve_within(root, "sub/link/secret.txt"))

    def test_empty_relative_is_the_root_itself(self):
        self.assertEqual(resolve_within(self.ROOT, ""), Path(self.ROOT).resolve())


class TestAssertDisposable(unittest.TestCase):
    """The rmtree in _create_worktree used to be justified by a naming
    convention. A convention is not a check on a value from the API."""

    def test_our_worktree_is_allowed(self):
        assert_disposable(f"/tmp/{WORKTREE_PREFIX}owner-repo-orca-1")

    def test_a_directory_outside_tmp_is_refused(self):
        with self.assertRaises(RuntimeError):
            assert_disposable("/home/someone/project")

    def test_tmp_itself_is_refused(self):
        with self.assertRaises(RuntimeError):
            assert_disposable("/tmp")

    def test_an_unrelated_tmp_directory_is_refused(self):
        with self.assertRaises(RuntimeError):
            assert_disposable("/tmp/someone-elses-build")

    def test_a_nested_path_is_refused(self):
        """Only the worktree itself is disposable, never something under it."""
        with self.assertRaises(RuntimeError):
            assert_disposable(f"/tmp/{WORKTREE_PREFIX}x/src")

    def test_create_worktree_checks_before_removing(self):
        src = __import__("inspect").getsource(orchestrator._create_worktree)
        self.assertIn("assert_disposable(path)", src)
        self.assertLess(src.index("assert_disposable(path)"),
                        src.index("shutil.rmtree"))


class TestDeclaredPaths(unittest.TestCase):
    """`git add -A` committed whatever the agent's Bash left behind."""

    def _task(self, files):
        return AlertTask(
            alert_id="orca-1", title="t", risk_level="high", feature_type="sast",
            source="app.py:1", alert_json={}, worktree_path=Path("/tmp/orca-fix-x"),
            fix_result=FixAgentResult(success=True, files_changed=files),
        )

    def test_reported_files_are_returned_relative_and_sorted(self):
        self.assertEqual(_declared_paths(self._task(["b.py", "a/c.py"])),
                         ["a/c.py", "b.py"])

    def test_line_suffix_is_stripped(self):
        self.assertEqual(_declared_paths(self._task(["app.py:40"])), ["app.py"])

    def test_duplicates_collapse(self):
        self.assertEqual(_declared_paths(self._task(["a.py", "a.py"])), ["a.py"])

    def test_a_path_outside_the_worktree_fails_the_alert(self):
        with self.assertRaises(RuntimeError):
            _declared_paths(self._task(["../../etc/passwd"]))

    def test_an_absolute_path_fails_the_alert(self):
        with self.assertRaises(RuntimeError):
            _declared_paths(self._task(["/etc/passwd"]))

    def test_nothing_reported_fails_rather_than_staging_everything(self):
        with self.assertRaises(RuntimeError):
            _declared_paths(self._task([]))

    def test_commit_stages_by_name_not_wholesale(self):
        import inspect
        src = inspect.getsource(orchestrator._commit_and_pr)
        self.assertIn("_declared_paths(task)", src)
        self.assertNotIn('"git", "add", "-A"', src)

    def test_retry_push_is_scoped_the_same_way(self):
        import inspect
        src = inspect.getsource(orchestrator._push_fix_update)
        self.assertIn("_declared_paths(task)", src)
        self.assertNotIn('"-A"', src)


class TestUnaccountedChangesBlockTheCommit(unittest.TestCase):
    """Staging by name is only half of it: a leftover is either an
    under-reported fix or a stray artefact, and we cannot tell which."""

    def test_leftover_untracked_file_raises(self):
        import run_agent
        with patch.object(run_agent, "run") as run:
            run.return_value = ("?? scratch.env", "", 0)
            with self.assertRaises(RuntimeError):
                run_agent._stage(["app.py"])

    def test_leftover_unstaged_modification_raises(self):
        import run_agent
        with patch.object(run_agent, "run") as run:
            run.return_value = (" M other.py", "", 0)
            with self.assertRaises(RuntimeError):
                run_agent._stage(["app.py"])

    def test_clean_tree_commits(self):
        import run_agent
        with patch.object(run_agent, "run") as run:
            run.return_value = ("M  app.py", "", 0)
            run_agent._stage(["app.py"])  # must not raise

    def test_no_paths_keeps_the_blanket_stage_for_manual_use(self):
        import run_agent
        with patch.object(run_agent, "run") as run:
            run.return_value = ("", "", 0)
            run_agent._stage([])
            self.assertEqual(run.call_args_list[0].args[0],
                             [*run_agent.SAFE_GIT, "add", "-A"])


class TestClonedTreesCannotConfigureTheAgent(unittest.TestCase):
    """A repository configures Claude Code just by containing files. The fix
    agent runs with cwd inside a repo cloned from the tenant."""

    def test_fix_agent_pins_its_configuration(self):
        for flag in ("--safe-mode", "--setting-sources", "--settings",
                     "--strict-mcp-config"):
            self.assertIn(flag, orchestrator._PINNED_CONFIG_FLAGS, flag)

    def test_settings_file_is_plugin_owned_and_exists(self):
        settings = Path(orchestrator._AGENT_SETTINGS)
        self.assertTrue(settings.is_file(), settings)
        self.assertIn("agent-settings.json", str(settings))

    def test_settings_file_is_valid_json(self):
        import json
        json.loads(Path(orchestrator._AGENT_SETTINGS).read_text())

    def test_setting_sources_excludes_the_clones_own(self):
        flags = orchestrator._PINNED_CONFIG_FLAGS
        sources = flags[flags.index("--setting-sources") + 1]
        self.assertNotIn("project", sources)
        self.assertNotIn("local", sources)

    def test_the_flags_reach_the_subprocess(self):
        import inspect
        src = inspect.getsource(orchestrator._invoke_fix_agent)
        self.assertIn("*_PINNED_CONFIG_FLAGS", src)


class TestAlertPathsCannotEscapeTheWorktree(unittest.TestCase):
    """The same join, at the three other places an alert field reaches one."""

    def test_project_root_ignores_a_traversing_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(
                validator._find_project_root(["../../etc/passwd"], root, "go.mod"),
                root.resolve())

    def test_terraform_root_ignores_a_traversing_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(
                validator._find_terraform_root(["../../etc/x.tf"], root), root.resolve())

    def test_package_identity_refuses_a_traversing_manifest(self):
        src = __import__("inspect").getsource(package_identity.identify_package)
        self.assertIn("resolve_within(worktree_path, manifest_rel)", src)

    def test_cve_verify_refuses_a_traversing_manifest(self):
        from pipelines import cve
        src = __import__("inspect").getsource(cve.CvePipeline.verify)
        self.assertIn("resolve_within(worktree_path, manifest_rel)", src)


def _git_version() -> tuple:
    import re
    import subprocess
    out = subprocess.run(["git", "--version"], capture_output=True, text=True).stdout
    match = re.search(r"(\d+)\.(\d+)", out)
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


class TestRepoHooksDoNotRunOnPluginGit(unittest.TestCase):
    """`git commit` and `git push` run the repository's hooks — husky,
    pre-commit, pre-push — with this process's credentials in the environment.
    In single-repo mode those are the operator's own hooks, live; and a regen
    command that executes repository code can point core.hooksPath anywhere
    mid-run. Plugin-run git must not execute any of them."""

    HOOKS = ("pre-commit", "prepare-commit-msg", "commit-msg", "post-commit",
             "pre-push", "post-checkout", "post-index-change", "reference-transaction")

    def setUp(self):
        import subprocess
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.markers = base / "markers"
        self.markers.mkdir()
        hooks = base / "hooks"
        hooks.mkdir()
        for name in self.HOOKS:
            hook = hooks / name
            hook.write_text(f"#!/bin/sh\ntouch '{self.markers / name}'\nexit 0\n")
            hook.chmod(0o755)
        # Nothing from the developer's own git config may leak in: a global
        # gpgsign or hooksPath would change what this test measures.
        self.env = patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": os.devnull,
                                           "GIT_CONFIG_NOSYSTEM": "1"})
        self.env.start()
        # The plugin's git reads its snapshot of the global config; take it
        # from the empty config above, not from the developer's own.
        self._saved_snapshot = agent_env._snapshot_path
        agent_env._reset_git_config_snapshot()
        self.remote = base / "remote.git"
        self.work = base / "work"
        git = lambda *a, cwd=None: subprocess.run(  # noqa: E731
            ["git", *a], cwd=cwd, check=True, capture_output=True, text=True)
        self.git = git
        git("init", "-q", "--bare", "-b", "main", str(self.remote))
        git("init", "-q", "-b", "main", str(self.work))
        for key, value in (("user.name", "t"), ("user.email", "t@example.com"),
                           ("commit.gpgsign", "false")):
            git("config", key, value, cwd=self.work)
        # Fetch URL on GitHub, as run_agent reads the repo name from it; pushes
        # go to the local bare repository.
        git("remote", "add", "origin", "https://github.com/owner/repo.git", cwd=self.work)
        git("remote", "set-url", "--push", "origin", str(self.remote), cwd=self.work)
        (self.work / "app.py").write_text("x = 1\n")
        git("add", "app.py", cwd=self.work)
        git("commit", "-q", "-m", "init", cwd=self.work)
        git("push", "-q", "origin", "main", cwd=self.work)
        # Installed last, the way husky's `prepare` script would, so the setup
        # commits above leave no markers behind.
        git("config", "core.hooksPath", str(hooks), cwd=self.work)
        # Two more ways config alone runs a command, neither reached by
        # core.hooksPath: config-defined hooks (git >= 2.54) and an fsmonitor.
        for event in self.HOOKS:
            git("config", "--add", "hook.planted.event", event, cwd=self.work)
        git("config", "hook.planted.command",
            # `; :` swallows the hook arguments git appends to a oneliner.
            f"touch '{self.markers / 'config-hook'}'; :", cwd=self.work)
        fsmonitor = base / "fsmonitor"
        fsmonitor.write_text(f"#!/bin/sh\ntouch '{self.markers / 'fsmonitor'}'\nexit 1\n")
        fsmonitor.chmod(0o755)
        git("config", "core.fsmonitor", str(fsmonitor), cwd=self.work)
        self.cwd = os.getcwd()
        os.chdir(self.work)

    def tearDown(self):
        os.chdir(self.cwd)
        self.env.stop()
        agent_env._snapshot_path = self._saved_snapshot
        self._tmp.cleanup()

    def fired(self):
        return sorted(p.name for p in self.markers.iterdir())

    def test_the_hooks_do_fire_on_a_plain_commit(self):
        """Positive control: without it a hook that never runs passes vacuously."""
        (self.work / "app.py").write_text("x = 2\n")
        self.git("commit", "-q", "-am", "plain", cwd=self.work)
        self.assertIn("pre-commit", self.fired())
        self.assertIn("post-commit", self.fired())
        self.assertIn("fsmonitor", self.fired())
        if _git_version() >= (2, 54):
            self.assertIn("config-hook", self.fired())

    def test_commit_push_and_retry_push_run_no_hook(self):
        import argparse
        import contextlib
        import io
        import subprocess

        import run_agent
        from orca_client import alert_branch_name

        branch = alert_branch_name("orca-1")
        self.git("checkout", "-q", "-b", branch, cwd=self.work)
        self.git("branch", "leftover", cwd=self.work)
        for path in self.markers.iterdir():  # the setup above fires hooks of its own
            path.unlink()

        real_run = run_agent.run

        def no_gh(cmd, **kw):
            if cmd[0] == "gh":
                return "https://github.com/owner/repo/pull/1", "", 0
            return real_run(cmd, **kw)

        (self.work / "app.py").write_text("x = 3\n")
        validator.worktree_diff(self.work)   # the first git call after the agent
        with patch.object(run_agent, "run", side_effect=no_gh), \
             contextlib.redirect_stdout(io.StringIO()):
            run_agent.cmd_git_commit(argparse.Namespace(
                dry_run=False, alert_id="orca-1", message="fix", path=["app.py"]))
            run_agent.cmd_open_pr(argparse.Namespace(
                dry_run=False, alert_id="orca-1", title="t", body="b"))

        (self.work / "app.py").write_text("x = 4\n")
        task = AlertTask(alert_id="orca-1", title="t", risk_level="high",
                         feature_type="sast", source="app.py:1", alert_json={},
                         worktree_path=self.work,
                         fix_result=FixAgentResult(success=True, files_changed=["app.py"]))
        orchestrator._push_fix_update(task)
        orchestrator._revert(self.work)
        orchestrator._remove_worktree(None, "leftover")

        self.assertEqual(self.fired(), [], "a repository hook ran on plugin git")
        self.assertNotIn("leftover", self.git("branch", cwd=self.work).stdout)
        pushed = subprocess.run(["git", f"--git-dir={self.remote}", "log",
                                 "--format=%s", branch, "--"],
                                capture_output=True, text=True, check=True).stdout
        self.assertEqual(pushed.split(), ["fix(security):", "retry", "fix", "for",
                                          "orca-1", "fix", "init"])

    def test_the_clone_is_hookless_from_the_start(self):
        """gh repo clone runs git clone, whose checkout can fire a template's
        post-checkout; the flag also persists into the clone's own config."""
        src = __import__("inspect").getsource(orchestrator._clone_repo)
        self.assertIn("core.hooksPath=/dev/null", src)

    def test_worktree_lifecycle_is_hookless(self):
        """`worktree add` fires post-checkout; `branch -D` fires
        reference-transaction, in the finally after every alert."""
        inspect = __import__("inspect")
        for fn in (orchestrator._create_worktree, orchestrator._remove_worktree):
            src = inspect.getsource(fn)
            with self.subTest(fn.__name__):
                self.assertNotIn('["git", ', src)
                self.assertIn("SAFE_GIT", src)


class TestFixAgentCannotRewriteGitConfig(unittest.TestCase):
    """Overriding hooks per command covers the keys we know about. A fix agent's
    regen runs repository code that can write any git config — credential.helper,
    core.sshCommand, an include.path — and the orchestrator's git then runs with
    our credentials. So the effective config is compared across every fix-agent
    run, and any change fails the alert before plugin git touches the tree."""

    def setUp(self):
        import subprocess
        self._tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": os.devnull,
                                           "GIT_CONFIG_NOSYSTEM": "1"})
        self.env.start()
        # The plugin's git reads its snapshot of the global config; take it
        # from the empty config above, not from the developer's own.
        self._saved_snapshot = agent_env._snapshot_path
        agent_env._reset_git_config_snapshot()
        self.work = Path(self._tmp.name) / "work"
        self.git = lambda *a: subprocess.run(
            ["git", *a], cwd=self.work, check=True, capture_output=True, text=True)
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.work)], check=True)
        self.included = Path(self._tmp.name) / "included.cfg"
        self.included.write_text("[user]\n\tname = t\n")
        self.git("config", "include.path", str(self.included))

    def tearDown(self):
        self.env.stop()
        agent_env._snapshot_path = self._saved_snapshot
        self._tmp.cleanup()

    def test_unchanged_config_is_not_drift(self):
        before = orchestrator._git_config_snapshot(self.work)
        self.assertTrue(before)
        self.assertEqual(orchestrator._config_drift(self.work, before), "")

    def test_each_kind_of_rewrite_is_caught(self):
        for desc, change in (
                ("credential helper", lambda: self.git("config", "credential.helper", "!evil")),
                ("ssh command", lambda: self.git("config", "core.sshCommand", "evil")),
                ("config hook", lambda: self.git("config", "hook.x.command", "evil")),
                ("included file", lambda: self.included.write_text(
                    "[core]\n\tfsmonitor = evil\n"))):
            with self.subTest(desc):
                before = orchestrator._git_config_snapshot(self.work)
                change()
                self.assertIn("git config changed",
                              orchestrator._config_drift(self.work, before), desc)

    def test_a_config_change_fails_the_alert_before_any_gate(self):
        from orca_client import Repository
        task = AlertTask(alert_id="orca-1", title="t", risk_level="high",
                         feature_type="sast", source="app.py:1", alert_json={})

        def agent(*_a, **_kw):
            self.git("config", "credential.helper", "!evil")
            return FixAgentResult(success=True, files_changed=["app.py"])

        with patch("orchestrator._create_worktree", return_value=self.work), \
             patch("orchestrator._remove_worktree"), \
             patch("orchestrator._invoke_fix_agent", side_effect=agent), \
             patch("orchestrator.sanity_check") as sanity:
            result = orchestrator.run_one(task, dry_run=False,
                                          notifier=unittest.mock.MagicMock(),
                                          repo=Repository(name="o/r", url="u",
                                                          clone_path=self.work))
        self.assertEqual(result.state, "FAILED")
        self.assertIn("git config changed", result.failure_reason)
        sanity.assert_not_called()

    def test_every_step_after_repository_code_is_checked(self):
        """Repository code (agent, build check) runs shared; every git step after
        it runs inside checked(), which holds the clone exclusively and proves
        the config unchanged first."""
        import re
        src = __import__("inspect").getsource(orchestrator._run_pipeline)
        for call in ("_invoke_fix_agent(", "pipeline.verify("):
            for m in re.finditer(re.escape(call), src):
                with self.subTest(call=call, at=m.start()):
                    self.assertIn("with gate.shared():", src[max(0, m.start() - 80):m.start()])
        for step in ("_revert(task.worktree_path)", "worktree_diff(task.worktree_path)",
                     "_get_diff(task.worktree_path)", "_commit_and_pr(task",
                     "_push_fix_update(task)"):
            for m in re.finditer(re.escape(step), src):
                with self.subTest(step=step, at=m.start()):
                    self.assertIn("checked(", src[max(0, m.start() - 80):m.start()])


class TestPlantedGitCommandsGetNoCredentials(unittest.TestCase):
    """After repository code ran, a clone's config can make a local git call run
    a command: an external diff, a textconv, a clean filter, an fsmonitor, a
    credential helper. Plugin git that needs no credential must hand none over.

    This proves what such a command *receives in its environment*. It still runs
    as the operator with the real HOME; the drift check is what stops it running
    at all — see TestFixAgentCannotRewriteGitConfig."""

    CANARIES = {"ORCA_API_TOKEN": "canary-orca", "GH_TOKEN": "canary-gh",
                "GITHUB_TOKEN": "canary-github", "NOTIFY_WEBHOOK_URL": "canary-hook",
                "ANTHROPIC_API_KEY": "canary-anthropic"}

    def setUp(self):
        import subprocess
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.markers = base / "markers"
        self.markers.mkdir()
        self.env = patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": os.devnull,
                                           "GIT_CONFIG_NOSYSTEM": "1", **self.CANARIES})
        self.env.start()
        self._saved_snapshot = agent_env._snapshot_path
        agent_env._reset_git_config_snapshot()
        self.work = base / "work"
        self.git = lambda *a, **kw: subprocess.run(
            ["git", *a], cwd=self.work, capture_output=True, text=True,
            **({"stdin": subprocess.DEVNULL} if "input" not in kw else {}), **kw)
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.work)], check=True)
        for key, value in (("user.name", "t"), ("user.email", "t@e"),
                           ("commit.gpgsign", "false")):
            self.git("config", key, value)
        (self.work / "app.py").write_text("x = 1\n")
        self.git("add", "app.py")
        self.git("commit", "-qm", "init")
        # Planted after the fact, as repository code during a fix would.
        for name, passthrough in (("external", False), ("textconv", True),
                                  ("filter", True), ("fsmonitor", False),
                                  ("credential", False)):
            script = base / name
            body = ('cat "$1"' if name == "textconv" else "cat") if passthrough else "exit 1"
            script.write_text(f"#!/bin/sh\nenv > '{self.markers}/{name}-$$'\n{body}\n")
            script.chmod(0o755)
        for key, value in (("diff.external", base / "external"),
                           ("diff.planted.textconv", base / "textconv"),
                           ("filter.planted.clean", base / "filter"),
                           ("filter.planted.smudge", base / "filter"),
                           ("core.fsmonitor", base / "fsmonitor"),
                           ("credential.helper", base / "credential")):
            self.git("config", key, str(value))
        (self.work / ".git" / "info").mkdir(exist_ok=True)
        (self.work / ".git" / "info" / "attributes").write_text(
            "* filter=planted diff=planted\n")
        (self.work / "app.py").write_text("x = 2\n")

    def tearDown(self):
        self.env.stop()
        agent_env._snapshot_path = self._saved_snapshot
        self._tmp.cleanup()

    def _fired(self):
        return {p.name.split("-")[0]: p.read_text() for p in self.markers.iterdir()}

    def _clear(self):
        for path in self.markers.iterdir():
            path.unlink()

    def test_the_planted_commands_do_fire_with_credentials_on_plain_git(self):
        """Positive control: each planted command runs, and sees the canaries."""
        self.git("diff")
        self.git("diff", "--no-ext-diff")
        self.git("status")
        self.git("credential", "fill", input="protocol=https\nhost=example.com\n\n",
                 env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
        fired = self._fired()
        for name in ("external", "textconv", "filter", "fsmonitor", "credential"):
            with self.subTest(name):
                self.assertIn(name, fired)
                self.assertIn("canary-gh", fired[name])

    def test_plugin_git_hands_planted_commands_no_credential(self):
        validator.worktree_diff(self.work)
        orchestrator._local_branch_exists("main", str(self.work))
        orchestrator._revert(self.work)
        fired = self._fired()
        for name in ("external", "textconv", "fsmonitor", "credential"):
            with self.subTest(name):
                self.assertNotIn(name, fired, f"{name} ran at all")
        self.assertIn("filter", fired, "filters are not overridden (LFS needs them)")
        for name, dump in fired.items():
            for canary in self.CANARIES.values():
                with self.subTest(command=name, canary=canary):
                    self.assertNotIn(canary, dump)

    def test_the_push_prefix_runs_only_the_operators_credential_helpers(self):
        """`credential.helper=` empties the list — generic and URL-scoped helpers
        from every config file — and the snapshot's are added back."""
        import subprocess
        base = Path(self._tmp.name)
        good = base / "good-helper"
        good.write_text(f"#!/bin/sh\ntouch '{self.markers}/good-$$'\nexit 0\n")
        good.chmod(0o755)
        operator = base / "operator.cfg"
        operator.write_text(f'[credential "https://example.com"]\n\thelper = {good}\n')
        with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(operator)}):
            agent_env._reset_git_config_snapshot()
            agent_env.git_config_snapshot()
        self.git("config", "credential.https://example.com.helper", str(base / "credential"))
        subprocess.run([*agent_env.push_git(), "credential", "fill"], cwd=self.work,
                       input="protocol=https\nhost=example.com\n\n", capture_output=True,
                       text=True, env=agent_env.credentialed_env())
        fired = self._fired()
        self.assertIn("good", fired)
        self.assertNotIn("credential", fired)

    def test_credentialed_calls_still_withhold_orca_and_model_credentials(self):
        env = agent_env.credentialed_env()
        self.assertIn("GH_TOKEN", env, "gh and push need GitHub's")
        for name in ("ORCA_API_TOKEN", "NOTIFY_WEBHOOK_URL", "ANTHROPIC_API_KEY"):
            self.assertNotIn(name, env)

    def test_every_gh_call_runs_outside_the_clone_with_a_named_repo(self):
        import inspect
        import re

        import run_agent
        for module in (orchestrator, validator, run_agent):
            src = inspect.getsource(module)
            for call in re.finditer(r'\[\s*"gh",', src):
                window = src[call.start():call.start() + 500]
                with self.subTest(module=module.__name__, at=call.start()):
                    self.assertIn("neutral_dir()", window)
                    self.assertIn("credentialed_env()", window)
        self.assertIn('"--repo", repo', inspect.getsource(run_agent.cmd_open_pr))


class TestPluginGitDoesNotPoisonItsOwnClone(unittest.TestCase):
    """The drift check compares the clone's config against its baseline, so git
    the plugin runs itself must not write config: `push -u` records the
    upstream in .git/config, `worktree add -b` does too under
    branch.autoSetupMerge=always, and either would poison every alert after."""

    def setUp(self):
        import subprocess
        orchestrator._reset_clone_guards()
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        operator = base / "operator.cfg"
        operator.write_text("[branch]\n\tautoSetupMerge = always\n"
                            "[user]\n\tname = t\n\temail = t@example.com\n"
                            "[commit]\n\tgpgsign = false\n")
        self.env = patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(operator),
                                           "GIT_CONFIG_NOSYSTEM": "1"})
        self.env.start()
        self._saved_snapshot = agent_env._snapshot_path
        agent_env._reset_git_config_snapshot()
        self.remote = base / "remote.git"
        self.clone = base / "clone"
        self.worktree = base / "orca-fix-o-r-orca-1"
        git = lambda *a, cwd=None: subprocess.run(  # noqa: E731
            ["git", *a], cwd=cwd, check=True, capture_output=True, text=True,
            stdin=subprocess.DEVNULL)
        git("init", "-q", "--bare", "-b", "main", str(self.remote))
        git("init", "-q", "-b", "main", str(self.clone))
        git("remote", "add", "origin", "https://github.com/owner/repo.git", cwd=self.clone)
        git("remote", "set-url", "--push", "origin", str(self.remote), cwd=self.clone)
        (self.clone / "app.py").write_text("x = 1\n")
        git("add", "app.py", cwd=self.clone)
        git("commit", "-qm", "init", cwd=self.clone)
        git("push", "-q", "origin", "main", cwd=self.clone)
        self.repo = Repository(name="owner/repo", url="u", clone_path=self.clone)
        self.cwd = os.getcwd()

    def tearDown(self):
        os.chdir(self.cwd)
        self.env.stop()
        agent_env._snapshot_path = self._saved_snapshot
        orchestrator._reset_clone_guards()
        self._tmp.cleanup()

    def _assert_unchanged(self, step):
        with self.subTest(step):
            self.assertEqual(orchestrator._config_drift(self.clone, self.baseline), "")

    def test_the_whole_git_lifecycle_leaves_the_config_as_it_found_it(self):
        import argparse
        import contextlib
        import io

        import run_agent
        self.baseline = orchestrator._record_config_baseline(self.repo)
        with patch("orchestrator._worktree_path", return_value=self.worktree):
            path = orchestrator._create_worktree("orca-1", "fix/orca-orca-1", repo=self.repo)
        self._assert_unchanged("worktree add")

        os.chdir(path)
        (path / "app.py").write_text("x = 2\n")
        real_run = run_agent.run

        def no_gh(cmd, **kw):
            if cmd[0] == "gh":
                return "https://github.com/owner/repo/pull/1", "", 0
            return real_run(cmd, **kw)

        with patch.object(run_agent, "run", side_effect=no_gh), \
             contextlib.redirect_stdout(io.StringIO()):
            run_agent.cmd_git_commit(argparse.Namespace(
                dry_run=False, alert_id="orca-1", message="fix", path=["app.py"]))
            self._assert_unchanged("commit")
            run_agent.cmd_open_pr(argparse.Namespace(
                dry_run=False, alert_id="orca-1", title="t", body="b"))
        self._assert_unchanged("push and open PR")

        (path / "app.py").write_text("x = 3\n")
        task = AlertTask(alert_id="orca-1", title="t", risk_level="high",
                         feature_type="sast", source="app.py:1", alert_json={},
                         worktree_path=path,
                         fix_result=FixAgentResult(success=True, files_changed=["app.py"]))
        orchestrator._push_fix_update(task)
        self._assert_unchanged("retry push")
        os.chdir(self.cwd)

        orchestrator._remove_worktree(path, "fix/orca-orca-1", repo=self.repo)
        self._assert_unchanged("teardown")

    def test_a_write_by_plugin_git_inside_a_checked_step_is_absorbed(self):
        """Writes plugin git makes that cannot be listed in advance (git-lfs
        records lfs.*.access) are folded into the baseline, since the check
        before the step passed and no repository code runs while it holds the
        clone."""
        import subprocess

        from impact_agent import ImpactResult
        from validator import ValidationResult

        task = AlertTask(alert_id="orca-1", title="t", risk_level="high",
                         feature_type="sast", source="app.py:1", alert_json={})

        def commit_and_pr(t, impact, dry_run):
            subprocess.run(["git", "config", "lfs.https://example.com/info/lfs.access",
                            "basic"], cwd=self.clone, check=True)
            return "https://github.com/owner/repo/pull/1"

        ok = ValidationResult(passed=True, phase="x")
        with patch("orchestrator._create_worktree", return_value=self.clone), \
             patch("orchestrator._remove_worktree") as remove, \
             patch("orchestrator._invoke_fix_agent", return_value=FixAgentResult(
                 success=True, files_changed=["app.py"], diff_summary="d")), \
             patch("orchestrator.worktree_diff", return_value="diff"), \
             patch("orchestrator.sanity_check", return_value=ok), \
             patch("orchestrator.llm_validate",
                   return_value=ValidationResult(passed=True, phase="llm", outcome="pass")), \
             patch("pipelines.base.local_build_check", return_value=ok), \
             patch("orchestrator.analyze_impact", return_value=ImpactResult(
                 level="low", description="", downtime_risk=False, requires_deploy=True)), \
             patch("orchestrator._commit_and_pr", side_effect=commit_and_pr), \
             patch("orchestrator.orca_check_gate", return_value=ok), \
             patch("orchestrator.ci_gate", return_value=ok), \
             patch("orchestrator._add_label"), \
             patch("orchestrator._sync_pr_body"):
            result = orchestrator.run_one(task, dry_run=False,
                                          notifier=unittest.mock.MagicMock(), repo=self.repo)
        self.assertEqual(result.state, "DONE", result.failure_reason)
        self.assertFalse(orchestrator._clone_gate(self.repo).poisoned)
        remove.assert_called_once()


class TestCloneGate(unittest.TestCase):
    """Up to four alerts share a clone. Repository code runs shared; the config
    check and the git that relies on it run exclusive, so an agent cannot
    rewrite the config between another alert's check and its push."""

    def test_repository_code_runs_concurrently(self):
        import threading
        gate = orchestrator._CloneGate()
        inside = threading.Barrier(2, timeout=2)

        def agent():
            with gate.shared():
                inside.wait()

        threads = [threading.Thread(target=agent) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(3)
        self.assertFalse(inside.broken, "two shared holders must overlap")

    def test_check_and_push_wait_for_running_agents(self):
        import threading
        import time
        gate = orchestrator._CloneGate()
        events = []
        agent_in = threading.Event()

        def agent():
            with gate.shared():
                agent_in.set()
                time.sleep(0.3)
                events.append("agent done")

        def push():
            agent_in.wait(2)
            with gate.exclusive():
                events.append("push")

        threads = [threading.Thread(target=agent), threading.Thread(target=push)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(3)
        self.assertEqual(events, ["agent done", "push"])

    def test_a_waiting_push_is_not_starved_by_new_agents(self):
        import threading
        import time
        gate = orchestrator._CloneGate()
        events = []
        first_in = threading.Event()

        def first_agent():
            with gate.shared():
                first_in.set()
                time.sleep(0.3)

        def push():
            with gate.exclusive():
                events.append("push")

        def late_agent():
            with gate.shared():
                events.append("late agent")

        a = threading.Thread(target=first_agent)
        a.start()
        first_in.wait(2)
        w = threading.Thread(target=push)
        w.start()
        time.sleep(0.1)          # the push is now waiting
        late = threading.Thread(target=late_agent)
        late.start()
        for t in (a, w, late):
            t.join(3)
        self.assertEqual(events, ["push", "late agent"])


class TestPoisonedCloneRunsNoMoreGit(unittest.TestCase):
    """Once a check finds the config changed, nothing else in that clone runs
    git: not the failing alert's teardown, not a later alert's worktree."""

    def setUp(self):
        import subprocess
        orchestrator._reset_clone_guards()
        self._tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": os.devnull,
                                           "GIT_CONFIG_NOSYSTEM": "1"})
        self.env.start()
        self._saved_snapshot = agent_env._snapshot_path
        agent_env._reset_git_config_snapshot()
        self.work = Path(self._tmp.name) / "work"
        subprocess.run(["git", "init", "-q", str(self.work)], check=True)
        self.repo = Repository(name="o/r", url="u", clone_path=self.work)

    def tearDown(self):
        self.env.stop()
        agent_env._snapshot_path = self._saved_snapshot
        orchestrator._reset_clone_guards()
        self._tmp.cleanup()

    def _task(self, n):
        return AlertTask(alert_id=f"orca-{n}", title="t", risk_level="high",
                         feature_type="sast", source="app.py:1", alert_json={})

    def test_later_alerts_fail_without_touching_git(self):
        import subprocess

        def poisoning_agent(*_a, **_kw):
            subprocess.run(["git", "config", "credential.helper", "!evil"],
                           cwd=self.work, check=True)
            return FixAgentResult(success=True, files_changed=["app.py"])

        with patch("orchestrator._create_worktree", return_value=self.work) as create, \
             patch("orchestrator._remove_worktree") as remove_with_git, \
             patch("orchestrator.assert_disposable"), \
             patch("orchestrator.shutil.rmtree") as rmtree, \
             patch("orchestrator._invoke_fix_agent", side_effect=poisoning_agent), \
             patch("orchestrator.worktree_diff") as diff:
            first = orchestrator.run_one(self._task(1), dry_run=False,
                                         notifier=unittest.mock.MagicMock(), repo=self.repo)
            second = orchestrator.run_one(self._task(2), dry_run=False,
                                          notifier=unittest.mock.MagicMock(), repo=self.repo)
        self.assertEqual(first.state, "FAILED")
        self.assertIn("git config changed", first.failure_reason)
        self.assertEqual(second.state, "FAILED")
        self.assertIn("git config changed", second.failure_reason)
        self.assertEqual(create.call_count, 1, "no worktree for the second alert")
        diff.assert_not_called()
        remove_with_git.assert_not_called()
        rmtree.assert_called_once()


class TestRepositoryCodeDoesNotOutliveItsRun(unittest.TestCase):
    """A child the fix agent or a build check leaves in the background could
    rewrite the config after the last check. It is killed with its group."""

    def test_a_background_child_is_killed(self):
        import subprocess
        import time
        with tempfile.TemporaryDirectory() as d:
            marker = Path(d) / "late-write"
            script = f"(sleep 1; touch '{marker}') >/dev/null 2>&1 & echo started"
            subprocess.run(["sh", "-c", script], capture_output=True, text=True)
            time.sleep(1.5)
            self.assertTrue(marker.exists(), "positive control: plain run leaves it")
            marker.unlink()
            result = agent_env.run_in_group(["sh", "-c", script])
            time.sleep(1.5)
            self.assertEqual(result.stdout, "started\n")
            self.assertFalse(marker.exists())

    def test_a_timeout_kills_the_whole_group(self):
        import subprocess
        import time
        with tempfile.TemporaryDirectory() as d:
            marker = Path(d) / "late-write"
            started = time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                agent_env.run_in_group(
                    ["sh", "-c", f"(sleep 1; touch '{marker}') & sleep 5"], timeout=0.3)
            self.assertLess(time.monotonic() - started, 2)
            time.sleep(1.2)
            self.assertFalse(marker.exists())

    def test_it_behaves_like_subprocess_run_otherwise(self):
        result = agent_env.run_in_group(["cat"], input="hello")
        self.assertEqual((result.returncode, result.stdout), (0, "hello"))
        self.assertEqual(agent_env.run_in_group(["sh", "-c", "exit 3"]).returncode, 3)
        with self.assertRaises(FileNotFoundError):
            agent_env.run_in_group(["no-such-binary-for-this-test"])

    def test_the_agent_and_the_build_checks_use_it(self):
        import inspect
        self.assertIn("run_in_group(", inspect.getsource(orchestrator._invoke_fix_agent))
        for name in ("_run_check", "_check_python"):
            self.assertIn("run_in_group(", inspect.getsource(getattr(validator, name)))


class TestConfigGuardFailsClosed(unittest.TestCase):
    """A guard that cannot read the config used to compare None with None and
    pass. Every way of not knowing now fails the alert."""

    def setUp(self):
        orchestrator._reset_clone_guards()
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.repo = Repository(name="o/r", url="u", clone_path=self.root)

    def tearDown(self):
        orchestrator._reset_clone_guards()
        self._tmp.cleanup()

    def _task(self):
        return AlertTask(alert_id="orca-1", title="t", risk_level="high",
                         feature_type="sast", source="app.py:1", alert_json={})

    def test_no_baseline_fails_before_any_worktree_git(self):
        with patch("orchestrator._git_config_snapshot", return_value=None), \
             patch("orchestrator._create_worktree") as create:
            result = orchestrator.run_one(self._task(), dry_run=False,
                                          notifier=unittest.mock.MagicMock(), repo=self.repo)
        self.assertEqual(result.state, "FAILED")
        self.assertIn("failing closed", result.failure_reason)
        create.assert_not_called()

    def test_an_unreadable_config_after_the_agent_fails_the_alert(self):
        # Readable for the baseline and the worktree creation, not after the agent.
        reads = iter(["cfg", "cfg"])
        with patch("orchestrator._git_config_snapshot",
                   side_effect=lambda _where: next(reads, None)), \
             patch("orchestrator._create_worktree", return_value=self.root), \
             patch("orchestrator._remove_worktree"), \
             patch("orchestrator._invoke_fix_agent",
                   return_value=FixAgentResult(success=True, files_changed=["a.py"])), \
             patch("orchestrator.sanity_check") as sanity:
            result = orchestrator.run_one(self._task(), dry_run=False,
                                          notifier=unittest.mock.MagicMock(), repo=self.repo)
        self.assertEqual(result.state, "FAILED")
        self.assertIn("could not list the git config", result.failure_reason)
        sanity.assert_not_called()

    def test_a_failed_read_is_not_cached_as_a_baseline(self):
        with patch("orchestrator._git_config_snapshot", side_effect=[None, "cfg"]):
            self.assertIsNone(orchestrator._record_config_baseline(self.repo))
            self.assertEqual(orchestrator._record_config_baseline(self.repo), "cfg")

    def test_the_clone_key_needs_no_git(self):
        """--path-format is git 2.31+; and git in a poisoned clone is the risk."""
        with patch("orchestrator.subprocess.run", side_effect=AssertionError("ran git")):
            self.assertEqual(orchestrator._clone_root(self.repo), str(self.root.resolve()))

    def test_without_show_scope_a_change_is_still_caught(self):
        import subprocess
        with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": os.devnull,
                                     "GIT_CONFIG_NOSYSTEM": "1"}):
            subprocess.run(["git", "init", "-q", str(self.root)], check=True)
            with patch("orchestrator._supports_show_scope", return_value=False):
                baseline = orchestrator._record_config_baseline(self.repo)
                self.assertNotIn("local\t", baseline)
                self.assertEqual(orchestrator._config_drift(self.root, baseline), "")
                subprocess.run(["git", "config", "credential.helper", "!evil"],
                               cwd=self.root, check=True)
                self.assertIn("git config changed",
                              orchestrator._config_drift(self.root, baseline))

    def test_baselines_are_recorded_before_any_repository_code(self):
        import inspect
        src = inspect.getsource(orchestrator._run_repo_pipeline)
        self.assertLess(src.index("_clone_repo(repo)"), src.index("_record_config_baseline(repo)"))
        self.assertLess(src.index("_record_config_baseline(repo)"),
                        src.index("pool.submit(run_one"))
        main = inspect.getsource(orchestrator.main)
        self.assertLess(main.index("_detect_repo()"), main.index("_record_config_baseline(repo)"))


class TestGitConfigIsReadOnceAtStart(unittest.TestCase):
    """Build checks keep the real HOME, so they can write ~/.gitconfig — and in
    --remote all, every later clone would read it. Plugin git reads a private
    snapshot of the operator's global and system config, taken once."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.included = base / "included.cfg"
        self.included.write_text("[user]\n\tname = from-include\n")
        self.global_cfg = base / "global.cfg"
        self.global_cfg.write_text(f"[core]\n\tsshCommand = ssh-original\n"
                                   f"[include]\n\tpath = {self.included}\n")
        self.env = patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(self.global_cfg),
                                           "GIT_CONFIG_NOSYSTEM": "1"})
        self.env.start()
        self._saved_snapshot = agent_env._snapshot_path
        agent_env._reset_git_config_snapshot()
        os.environ.pop(agent_env.GIT_SNAPSHOT_ENV, None)

    def tearDown(self):
        self.env.stop()
        agent_env._snapshot_path = self._saved_snapshot
        self._tmp.cleanup()

    def _get(self, key):
        import subprocess
        return subprocess.run(["git", "config", "--get", key], cwd=self._tmp.name,
                              capture_output=True, text=True,
                              env=agent_env.git_env()).stdout.strip()

    def test_a_rewritten_global_config_is_not_seen(self):
        snapshot = agent_env.git_config_snapshot()
        self.global_cfg.write_text("[core]\n\tsshCommand = ssh-evil\n")
        self.included.write_text("[user]\n\tname = evil\n")
        self.assertEqual(self._get("core.sshCommand"), "ssh-original")
        self.assertEqual(self._get("user.name"), "from-include")
        text = Path(snapshot).read_text().lower()
        self.assertNotIn("[include", text, "includes are inlined, not followed again")
        self.assertNotIn(str(self.included).lower(), text)
        self.assertNotIn("osxkeychain", text, "GIT_CONFIG_NOSYSTEM=1 is honoured")

    def test_the_snapshot_is_private(self):
        snapshot = Path(agent_env.git_config_snapshot())
        self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
        self.assertEqual(snapshot.parent.stat().st_mode & 0o777, 0o700)

    def test_child_processes_inherit_the_same_snapshot(self):
        env = agent_env.git_env()
        self.assertEqual(env[agent_env.GIT_SNAPSHOT_ENV], env["GIT_CONFIG_GLOBAL"])
        self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")
        agent_env._reset_git_config_snapshot()
        with patch.dict(os.environ, {agent_env.GIT_SNAPSHOT_ENV: env["GIT_CONFIG_GLOBAL"]}):
            self.assertEqual(agent_env.git_config_snapshot(), env["GIT_CONFIG_GLOBAL"])

    def test_old_git_fails_closed(self):
        with patch.object(agent_env, "_git_version", return_value=(2, 31)), \
             self.assertRaises(RuntimeError):
            agent_env.git_config_snapshot()

    def test_every_git_and_gh_call_site_passes_the_isolated_env(self):
        import inspect
        import re

        import run_agent
        for module in (orchestrator, validator, run_agent):
            src = inspect.getsource(module)
            for call in re.finditer(r"subprocess\.run\(\s*(\[[^\n]*?\]|cmd)", src):
                head = call.group(1)
                if not re.search(r'"git"|"gh"|HOOKLESS_GIT|^cmd$', head):
                    continue
                window = src[call.start():call.start() + 400]
                with self.subTest(module=module.__name__, call=head[:40]):
                    self.assertIn("env=", window)

    def test_the_clone_reads_the_snapshot(self):
        from orca_client import Repository
        snapshot = agent_env.git_config_snapshot()
        with patch("orchestrator.subprocess.run") as run, \
             patch("orchestrator.shutil.rmtree"):
            run.return_value.returncode = 0
            run.return_value.stdout = ""
            orchestrator._clone_repo(Repository(name="o/r", url="https://github.com/o/r"))
        env = run.call_args.kwargs["env"]
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], snapshot)


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_classes = [
        TestSafeName,
        TestResolveWithin,
        TestAssertDisposable,
        TestDeclaredPaths,
        TestUnaccountedChangesBlockTheCommit,
        TestClonedTreesCannotConfigureTheAgent,
        TestAlertPathsCannotEscapeTheWorktree,
        TestRepoHooksDoNotRunOnPluginGit,
        TestFixAgentCannotRewriteGitConfig,
        TestPlantedGitCommandsGetNoCredentials,
        TestPluginGitDoesNotPoisonItsOwnClone,
        TestCloneGate,
        TestPoisonedCloneRunsNoMoreGit,
        TestRepositoryCodeDoesNotOutliveItsRun,
        TestConfigGuardFailsClosed,
        TestGitConfigIsReadOnceAtStart,
    ]

    _registered = {cls.__name__ for cls in test_classes}
    _defined = {name for name, obj in list(globals().items())
                if isinstance(obj, type) and issubclass(obj, unittest.TestCase)
                and obj is not unittest.TestCase}
    _missing = sorted(_defined - _registered)
    if _missing:
        sys.exit(f"Test classes defined but never run — add them to "
                 f"test_classes: {', '.join(_missing)}")

    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    sys.exit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
