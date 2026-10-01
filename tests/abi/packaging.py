"""Tests that the packaging metadata around the ABI generator stays in sync.

Pure file checks over the source tree: they need no build dependencies and
run on every supported Python.
"""

import glob
import os
import re
import sys
import typing
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
TOOLS = os.path.join(ROOT, "tools", "abi")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

from common import INPUT_PATTERNS  # noqa: E402


def _pyproject() -> str:
    with open(os.path.join(ROOT, "pyproject.toml")) as fh:
        return fh.read()


def _toml_list(text: str, key: str) -> typing.List[str]:
    """The string items of the TOML array `key` (a line-per-item array)."""
    match = re.search(rf"^{re.escape(key)} = \[\n(.*?)^\]", text, re.M | re.S)
    if match is None:
        raise AssertionError(f"pyproject.toml has no {key} array")
    return re.findall(r'"((?:[^"\\]|\\.)*)"', match.group(1))


def _files(patterns: typing.Iterable[str], crossing: bool) -> typing.Set[str]:
    """Repository files matched by glob `patterns`; with `crossing`, ``*``
    also matches ``/`` (uv's cache-key semantics)."""
    found: typing.Set[str] = set()
    for pattern in patterns:
        if "*" not in pattern:
            if os.path.isfile(os.path.join(ROOT, pattern)):
                found.add(pattern)
        elif crossing:
            regex = re.compile(
                "^"
                + re.escape(pattern).replace(r"\*\*", ".*").replace(r"\*", ".*")
                + "$"
            )
            base = pattern.split("*", 1)[0].rsplit("/", 1)[0]
            for dirpath, _, filenames in os.walk(os.path.join(ROOT, base)):
                for filename in filenames:
                    rel = os.path.relpath(os.path.join(dirpath, filename), ROOT)
                    rel = rel.replace(os.sep, "/")
                    if regex.match(rel):
                        found.add(rel)
        else:
            for path in glob.glob(os.path.join(ROOT, pattern)):
                found.add(os.path.relpath(path, ROOT).replace(os.sep, "/"))
    return {f for f in found if "/__pycache__/" not in f and "/_data/" not in f}


class ABIPackagingTests(unittest.TestCase):
    def test_uv_cache_keys_cover_exactly_the_generator_inputs(self):
        keys = re.findall(
            r'\{ file = "([^"]+)" \}',
            re.search(r"^cache-keys = \[\n(.*?)^\]", _pyproject(), re.M | re.S).group(
                1
            ),
        )
        by_uv = _files(keys, crossing=True)
        by_generator = _files(INPUT_PATTERNS, crossing=False) | {"pyproject.toml"}
        self.assertEqual(sorted(by_uv - by_generator), [])
        self.assertEqual(sorted(by_generator - by_uv), [])

    def test_build_constraints_match_pyproject(self):
        with open(os.path.join(TOOLS, "build-constraints.txt")) as fh:
            listed = [
                line.strip()
                for line in fh
                if line.strip() and not line.lstrip().startswith("#")
            ]
        self.assertEqual(
            listed, _toml_list(_pyproject(), "build-constraint-dependencies")
        )
        names = [re.split(r"[=<>~!; ]", line, 1)[0] for line in listed]
        for name in ("angr", "pypcode", "pycparser", "z3-solver", "claripy"):
            self.assertIn(name, names)
        for generic in ("setuptools", "cffi", "numpy"):
            self.assertNotIn(generic, names)

    def test_wheel_ships_the_notices(self):
        text = _pyproject()
        license_files = _toml_list(text, "license-files")
        self.assertIn("LICENSE.txt", license_files)
        self.assertIn("smallworld/platforms/abi/NOTICE", license_files)
        self.assertIn("smallworld/platforms/abi/LICENSES/*.txt", license_files)
        abi = os.path.join(ROOT, "smallworld", "platforms", "abi")
        for name in (
            "NOTICE",
            "LICENSES/Apache-2.0.txt",
            "LICENSES/BSD-2-Clause-angr.txt",
            "LICENSES/BSD-2-Clause-archinfo.txt",
        ):
            self.assertTrue(os.path.isfile(os.path.join(abi, name)), name)
        with open(os.path.join(abi, "NOTICE")) as fh:
            notice = " ".join(fh.read().split())
        self.assertIn("derived from, and modify", notice)
        self.assertIn("National Security Agency", notice)

    def test_nix_fileset_carries_the_generator_and_the_license(self):
        with open(os.path.join(ROOT, "nix", "python-packages.nix")) as fh:
            nix = fh.read()
        self.assertIn("../tools/abi", nix)
        self.assertIn("../LICENSE.txt", nix)

    def test_sdist_manifest(self):
        with open(os.path.join(ROOT, "MANIFEST.in")) as fh:
            manifest = fh.read()
        self.assertIn("graft tools/abi", manifest)
        self.assertIn("prune smallworld/platforms/abi/_data", manifest)
