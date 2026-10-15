"""A hermetic git config snapshot for the test process.

Plugin git reads agent_env.git_config_snapshot(), taken lazily on first use. A
test that patches subprocess.run would otherwise be the one to take it, against
a mock, and every later test would inherit the developer's own ~/.gitconfig.
Importing this takes it once, up front, from an empty global and system config.
"""
import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

import agent_env


def prime() -> str:
    if agent_env._snapshot_path is None:
        with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": os.devnull,
                                     "GIT_CONFIG_NOSYSTEM": "1"}):
            os.environ.pop(agent_env.GIT_SNAPSHOT_ENV, None)
            agent_env.git_config_snapshot()
    return agent_env._snapshot_path


prime()


_STEADY = []


def steady_git_config():
    """setUpModule for suites that drive run_one with subprocess mocked.

    The clone guard fails closed when it cannot list git config, which under a
    mocked subprocess.run it never can. These suites test everything else, so
    the config reads as one constant, unchanged value for the whole module.
    """
    import orchestrator
    orchestrator._reset_clone_guards()
    patcher = patch("orchestrator._git_config_snapshot", return_value="steady-config")
    patcher.start()
    _STEADY.append(patcher)


def release_git_config():
    """tearDownModule partner of steady_git_config."""
    import orchestrator
    while _STEADY:
        _STEADY.pop().stop()
    orchestrator._reset_clone_guards()
