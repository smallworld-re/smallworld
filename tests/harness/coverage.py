from __future__ import annotations

import os
import pathlib
import re
import sys

_PYTHON_RE = re.compile(r"^python(?:3(?:\.\d+)*)?$")


def coverage_enabled(env: dict[str, str] | None = None) -> bool:
    source = os.environ if env is None else env
    return source.get("SMALLWORLD_COVERAGE") == "1"


def wrap_python_command(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
) -> list[str]:
    if not argv or not coverage_enabled(env):
        return argv
    if _is_coverage_command(argv):
        return argv
    if not _is_python_command(argv[0]):
        return argv

    wrapped = [
        argv[0],
        "-m",
        "coverage",
        "run",
        "--parallel-mode",
    ]
    rcfile = (env or os.environ).get("SMALLWORLD_COVERAGE_RCFILE")
    if rcfile:
        wrapped.extend(["--rcfile", rcfile])
    wrapped.extend(argv[1:])
    return wrapped


def _is_python_command(program: str) -> bool:
    if program == sys.executable:
        return True
    name = pathlib.Path(program).name
    return _PYTHON_RE.match(name) is not None


def _is_coverage_command(argv: list[str]) -> bool:
    if len(argv) < 4:
        return False
    return argv[1:4] == ["-m", "coverage", "run"]
