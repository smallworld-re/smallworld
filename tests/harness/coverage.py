from __future__ import annotations

import os
import pathlib
import re
import sys

_PYTHON_RE = re.compile(r"^python(?:3(?:\.\d+)*)?$")
_INTERPRETER_OPTIONS = frozenset(
    {
        "-b",
        "-B",
        "-d",
        "-E",
        "-i",
        "-I",
        "-O",
        "-OO",
        "-P",
        "-q",
        "-s",
        "-S",
        "-u",
        "-v",
        "-x",
    }
)
_INTERPRETER_OPTIONS_WITH_VALUE = frozenset(
    {
        "-W",
        "-X",
        "--check-hash-based-pycs",
    }
)


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

    split = _split_coverable_python_command(argv)
    if split is None:
        return argv
    interpreter_argv, target_argv = split

    wrapped = [argv[0], *interpreter_argv, "-m", "coverage", "run", "--parallel-mode"]
    rcfile = (env or os.environ).get("SMALLWORLD_COVERAGE_RCFILE")
    if rcfile:
        wrapped.extend(["--rcfile", rcfile])
    wrapped.extend(target_argv)
    return wrapped


def _is_python_command(program: str) -> bool:
    if program == sys.executable:
        return True
    name = pathlib.Path(program).name
    return _PYTHON_RE.match(name) is not None


def _is_coverage_command(argv: list[str]) -> bool:
    split = _split_python_command(argv)
    if split is None:
        return False
    _, target_argv = split
    return target_argv[:3] == ["-m", "coverage", "run"]


def _split_coverable_python_command(
    argv: list[str],
) -> tuple[list[str], list[str]] | None:
    split = _split_python_command(argv)
    if split is None:
        return None
    _, target_argv = split
    if not target_argv:
        return None
    if target_argv[0] == "-m":
        return split
    if target_argv[0].startswith("-"):
        return None
    return split


def _split_python_command(argv: list[str]) -> tuple[list[str], list[str]] | None:
    if not argv or not _is_python_command(argv[0]):
        return None

    interpreter_argv: list[str] = []
    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg == "-m":
            if index + 1 >= len(argv):
                return None
            return interpreter_argv, argv[index:]
        if arg in {"-c", "-"}:
            return None
        if not arg.startswith("-"):
            return interpreter_argv, argv[index:]
        if arg in _INTERPRETER_OPTIONS:
            interpreter_argv.append(arg)
            index += 1
            continue
        if arg in _INTERPRETER_OPTIONS_WITH_VALUE:
            if index + 1 >= len(argv):
                return None
            interpreter_argv.extend(argv[index : index + 2])
            index += 2
            continue
        if arg.startswith("-W") and arg != "-W":
            interpreter_argv.append(arg)
            index += 1
            continue
        if arg.startswith("-X") and arg != "-X":
            interpreter_argv.append(arg)
            index += 1
            continue
        if arg.startswith("--check-hash-based-pycs="):
            interpreter_argv.append(arg)
            index += 1
            continue
        return None
    return None
