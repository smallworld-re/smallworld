"""Helpers shared by the ABI generator's stages (stdlib only, Python >= 3.9)."""

import hashlib
import json
import sys
import typing

PREFIX = "smallworld ABI generator"

#: The source files the tables are generated from, relative to the source
#: root: the provenance manifest records their digests, and ``--if-stale``
#: regenerates when one changes.
INPUT_PATTERNS = (
    "tools/abi/*.py",
    "tools/abi/overlay/*.py",
    "smallworld/utils.py",
    "smallworld/exceptions/*.py",
    "smallworld/exceptions/unstable/*.py",
    "smallworld/platforms/*.py",
    "smallworld/platforms/defs/*.py",
    "smallworld/platforms/abi/*.py",
)


class GeneratorError(Exception):
    """A failure that must stop the build, with a message meant for people."""


def fail(message: str, code: int = 2) -> typing.NoReturn:
    """Print `message` as a generator error and exit with `code`."""
    sys.stderr.write(f"\n{PREFIX}: ERROR: {message}\n\n")
    sys.stderr.flush()
    raise SystemExit(code)


def dump_json(obj: typing.Any, path: str) -> None:
    """Write `obj` as sorted, indented JSON with a trailing newline."""
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True)
        fh.write("\n")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    with open(path, "rb") as fh:
        return sha256_bytes(fh.read())
