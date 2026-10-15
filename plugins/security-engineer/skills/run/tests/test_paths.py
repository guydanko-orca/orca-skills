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
                             [*run_agent.HOOKLESS_GIT, "add", "-A"])


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
        git("remote", "add", "origin", str(self.remote), cwd=self.work)
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
                self.assertIn("HOOKLESS_GIT", src)


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
                                          repo=Repository(name="o/r", url="u"))
        self.assertEqual(result.state, "FAILED")
        self.assertIn("git config changed", result.failure_reason)
        sanity.assert_not_called()

    def test_every_fix_agent_run_and_every_push_is_checked(self):
        """After each agent run, and before each commit or push — the build check
        between them runs repository code as well."""
        src = __import__("inspect").getsource(orchestrator._run_pipeline)
        guarded = (src.count("_invoke_fix_agent(") + src.count("_commit_and_pr(")
                   + src.count("_push_fix_update("))
        self.assertEqual(src.count('config_drifted("'), guarded)


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
