"""Unit tests for smallworld.platforms.abi (schema, registry, query API).

The shipped tables are generated at build/install time and are not in the
source tree, so these tests serve the hand-written records in
``abi/fixtures.py`` through ``registry._use_records`` (or by pointing the
registry's data module at the fixture module). They need no emulator and no
optional dependency, and they run on Python 3.9.
"""

import ast
import copy
import dataclasses
import gc
import importlib.util
import os
import pickle
import re
import subprocess
import sys
import sysconfig
import tempfile
import textwrap
import threading
import types
import typing
import unittest
import weakref
from unittest import mock

import smallworld
from smallworld import exceptions, platforms, utils
from smallworld.platforms import abi
from smallworld.platforms.abi import registry, validate

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS_DIR = os.path.dirname(HERE)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

from abi import fixtures  # noqa: E402

SMALLWORLD_DIR = os.path.dirname(os.path.abspath(smallworld.__file__))
ABI_DIR = os.path.join(SMALLWORLD_DIR, "platforms", "abi")

X86_64 = fixtures.X86_64
AARCH64 = fixtures.AARCH64


def _run_python(
    code: str,
    env: typing.Optional[typing.Dict[str, str]] = None,
    timeout: float = 300,
) -> str:
    """Run `code` in a fresh interpreter and return its stdout."""
    full_env = dict(os.environ)
    full_env["PYTHONPATH"] = os.pathsep.join(
        [TESTS_DIR] + [p for p in full_env.get("PYTHONPATH", "").split(os.pathsep) if p]
    )
    if env:
        full_env.update(env)
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        capture_output=True,
        text=True,
        env=full_env,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"subprocess failed ({result.returncode}):\n{result.stdout}\n{result.stderr}"
        )
    return result.stdout


class FixtureTestCase(unittest.TestCase):
    """Serve the fixture records for the duration of each test."""

    def setUp(self):
        context = registry._use_records(fixtures.RECORDS)
        context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.x86 = abi.resolve(X86_64)
        self.win = abi.resolve(X86_64, platforms.ABI.WINDOWS)
        self.a64 = abi.resolve(AARCH64)


# ---------------------------------------------------------------------------
# Import graph and bootstrap
# ---------------------------------------------------------------------------

#: What smallworld.platforms.abi may import (spec 3.2).
ALLOWED_SMALLWORLD = (
    "smallworld.platforms.abi",
    "smallworld.platforms.platforms",
    "smallworld.platforms.defs",
    "smallworld.platforms.naming",
    "smallworld.utils",
    "smallworld.exceptions.exceptions",
)
#: Packages whose ``__init__`` runs when an allowed module is imported, and
#: what those ``__init__`` modules import in turn.
IMPLIED_SMALLWORLD = frozenset(
    {
        "smallworld",
        "smallworld.platforms",
        "smallworld.exceptions",
        "smallworld.exceptions.unstable",
        "smallworld.exceptions.unstable.exceptions",
    }
)
ALLOWED_THIRD_PARTY = frozenset({"capstone"})
#: Allowed only inside function bodies (lazy imports).
FUNCTION_ONLY = frozenset({"lief", "elftools"})


def _is_stdlib(top: str) -> bool:
    names = getattr(sys, "stdlib_module_names", None)
    if names is not None:
        return top in names
    # Python 3.9 has no stdlib_module_names; locate the module instead.
    if top in sys.builtin_module_names:
        return True
    spec = importlib.util.find_spec(top)
    if spec is None or spec.origin is None:
        return False
    if spec.origin in ("built-in", "frozen"):
        return True
    stdlib = os.path.realpath(sysconfig.get_paths()["stdlib"])
    origin = os.path.realpath(spec.origin)
    return origin.startswith(stdlib + os.sep) and "site-packages" not in origin


def _module_allowed(name: str, in_function: bool) -> bool:
    if name == "smallworld" or name.startswith("smallworld."):
        return any(name == a or name.startswith(a + ".") for a in ALLOWED_SMALLWORLD)
    top = name.split(".")[0]
    if top in ALLOWED_THIRD_PARTY or _is_stdlib(top):
        return True
    return in_function and top in FUNCTION_ONLY


def import_violations(
    source: str, module: str, is_package: bool
) -> typing.List[typing.Tuple[int, str]]:
    """``(line, imported module)`` for every import in `source` (the text of
    `module`) that the ABI package's allow-list forbids."""
    package = module if is_package else module.rpartition(".")[0]
    violations: typing.List[typing.Tuple[int, str]] = []

    def check(node: ast.AST, in_function: bool) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if not _module_allowed(alias.name, in_function):
                    violations.append((node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parts = package.split(".")
                base = ".".join(parts[: len(parts) - node.level + 1])
                target = f"{base}.{node.module}" if node.module else base
            else:
                target = node.module or ""
            if _module_allowed(target, in_function):
                return
            # `from .. import platforms` imports the submodule
            # smallworld.platforms.platforms.
            if all(
                _module_allowed(f"{target}.{alias.name}", in_function)
                for alias in node.names
            ):
                return
            violations.append((node.lineno, target))
        in_function = in_function or isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
        )
        for child in ast.iter_child_nodes(node):
            check(child, in_function)

    check(ast.parse(source), False)
    return violations


class ABIImportGraphTests(unittest.TestCase):
    """smallworld.platforms.abi imports only its allow-list (spec 3.2)."""

    def _modules(self):
        for dirpath, _, filenames in os.walk(ABI_DIR):
            for filename in sorted(filenames):
                if not filename.endswith(".py"):
                    continue
                path = os.path.join(dirpath, filename)
                rel = os.path.relpath(path, os.path.dirname(SMALLWORLD_DIR))
                parts = rel[: -len(".py")].split(os.sep)
                is_package = parts[-1] == "__init__"
                if is_package:
                    parts = parts[:-1]
                yield path, ".".join(parts), is_package

    def test_static_import_allow_list(self):
        modules = list(self._modules())
        self.assertGreater(len(modules), 5)
        for path, module, is_package in modules:
            with self.subTest(module=module):
                with open(path) as f:
                    source = f.read()
                self.assertEqual(import_violations(source, module, is_package), [])

    def test_checker_flags_forbidden_imports(self):
        source = textwrap.dedent("""
            import angr
            from smallworld.state import cpus
            from ...emulators import unicorn
            from .. import platforms
            from ..defs import PlatformDef
            import lief

            def lazy():
                import lief
                import pypcode
            """)
        found = import_violations(source, "smallworld.platforms.abi.model", False)
        self.assertEqual(
            [name for _, name in found],
            [
                "angr",
                "smallworld.state",
                "smallworld.emulators",
                "lief",
                "pypcode",
            ],
        )

    def test_fresh_interpreter_imports_only_the_closure(self):
        # Load the package through a stub `smallworld` whose __init__ does not
        # run, so only what the ABI package itself pulls in gets imported, and
        # check that closure against the allow-list: this catches a
        # forbidden import made indirectly (by platforms.defs, say), which the
        # static check does not see. It also catches import cycles.
        out = _run_python(f"""
            import sys, types
            before = set(sys.modules)
            pkg = types.ModuleType("smallworld")
            pkg.__path__ = [{SMALLWORLD_DIR!r}]
            sys.modules["smallworld"] = pkg
            import smallworld.platforms.abi as abi
            assert abi.registry._loaded is None
            print("\\n".join(sorted(set(sys.modules) - before)))
            """)
        loaded = out.split()
        self.assertIn("smallworld.platforms.abi.registry", loaded)
        self.assertNotIn("smallworld.platforms.abi._data", loaded)
        bad = []
        for name in loaded:
            top = name.split(".")[0]
            if top == "smallworld":
                ok = name in IMPLIED_SMALLWORLD or any(
                    name == a or name.startswith(a + ".") for a in ALLOWED_SMALLWORLD
                )
            else:
                ok = (
                    top in ALLOWED_THIRD_PARTY
                    or _is_stdlib(top)
                    or top.startswith("_sysconfigdata")
                )
            if not ok:
                bad.append(name)
        self.assertEqual(bad, [])

    def test_import_smallworld_builds_no_registry(self):
        out = _run_python("""
            import sys
            import smallworld
            from smallworld.platforms import abi
            print("smallworld.platforms.abi._data" in sys.modules,
                  abi.registry._loaded is not None,
                  abi.registry._load_failure is not None,
                  abi.API_FEATURES == frozenset())
            """)
        self.assertEqual(out.split(), ["False", "False", "False", "True"])


# ---------------------------------------------------------------------------
# Registry and loader seam
# ---------------------------------------------------------------------------


class ABIRegistryLoaderTests(unittest.TestCase):
    """The data module may be absent or broken; lookups say so clearly."""

    def _with_data_module(self, name):
        patches = [
            mock.patch.object(registry, "DATA_MODULE", name),
            mock.patch.object(registry, "_loaded", None),
            mock.patch.object(registry, "_load_failure", None),
            mock.patch.object(registry, "_override", None),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_default_data_module(self):
        self.assertEqual(registry.DATA_MODULE, "smallworld.platforms.abi._data")

    def test_missing_tables_raise_on_lookup(self):
        self._with_data_module("smallworld.platforms.abi._no_such_tables")
        self.assertFalse(abi.tables_available())
        for call in (
            lambda: abi.resolve(X86_64),
            lambda: abi.maybe_resolve(X86_64),
            lambda: abi.by_id("X86_64/LITTLE:sysv"),
            lambda: abi.variants(X86_64),
            lambda: abi.all_records(),
        ):
            with self.assertRaises(abi.ABITablesUnavailable) as ctx:
                call()
            self.assertIsInstance(ctx.exception, exceptions.ConfigurationError)
            self.assertIn("no ABI tables are installed", str(ctx.exception))
            self.assertIsNone(ctx.exception.__cause__)

    def test_failed_load_is_cached_until_reset(self):
        name = "_sw_abi_late_tables"
        self._with_data_module(name)
        with mock.patch.object(
            registry.importlib, "import_module", wraps=importlib.import_module
        ) as import_module:
            self.assertFalse(abi.tables_available())
            with self.assertRaisesRegex(abi.ABITablesUnavailable, "no ABI tables"):
                abi.resolve(X86_64)
            self.assertEqual(abi.table_features(), frozenset())
            self.assertEqual(import_module.call_count, 1)
            # Tables that appear later in the process are not picked up...
            self._write_module(name, "from abi.fixtures import RECORDS\n")
            self.assertFalse(abi.tables_available())
            self.assertEqual(import_module.call_count, 1)
            # ...until the test hook forgets the failure.
            registry._reset()
            self.assertIs(abi.resolve(X86_64), fixtures.X86_64_SYSV)
            self.assertEqual(import_module.call_count, 2)

    def test_cached_failure_keeps_its_cause_as_text(self):
        self._write_module("_sw_abi_broken_tables2", "import _sw_abi_no_such_dep2\n")
        self._with_data_module("_sw_abi_broken_tables2")
        with self.assertRaisesRegex(abi.ABITablesUnavailable, "failed to load") as ctx:
            abi.resolve(X86_64)
        self.assertIsInstance(ctx.exception.__cause__, ModuleNotFoundError)
        # Later lookups re-raise the cached failure, whose cause is the
        # original chain formatted as text.
        for _ in range(2):
            with self.assertRaisesRegex(
                abi.ABITablesUnavailable, "failed to load"
            ) as ctx:
                abi.resolve(X86_64)
            cause = ctx.exception.__cause__
            self.assertIsInstance(cause, registry._LoadFailureCause)
            self.assertIn(
                "ModuleNotFoundError: No module named '_sw_abi_no_such_dep2'",
                str(cause),
            )

    def _assert_cached_failure_holds_no_frames(self, name, source):
        """The data module `source` fails to import, and in doing so stores
        a weakref to an object that only its frames reference in
        ``_sw_abi_holder.ref``. Once the first failing lookup is over,
        nothing the cache holds may keep that object alive."""
        holder = types.ModuleType("_sw_abi_holder")
        sys.modules["_sw_abi_holder"] = holder
        self.addCleanup(sys.modules.pop, "_sw_abi_holder", None)
        self._write_module(name, source)
        self._with_data_module(name)

        class Marker:
            pass

        def first_lookup():
            marker = Marker()
            try:
                abi.resolve(X86_64)
            except abi.ABITablesUnavailable:
                pass
            return weakref.ref(marker)

        caller_ref = first_lookup()
        gc.collect()
        self.assertIsNone(caller_ref())
        self.assertIsNone(holder.ref())  # type: ignore[attr-defined]
        failure = registry._load_failure
        self.assertIsNotNone(failure)
        self.assertIsNone(failure.__traceback__)
        self.assertIsInstance(failure.__cause__, registry._LoadFailureCause)
        self.assertEqual(failure.__cause__.args, (str(failure.__cause__),))
        # A later lookup still reports the cause, and pins nothing either.
        with self.assertRaises(abi.ABITablesUnavailable) as ctx:
            abi.resolve(X86_64)
        self.assertIsNone(registry._load_failure.__traceback__)
        return str(ctx.exception.__cause__)

    def test_cached_failure_holds_no_frames(self):
        text = self._assert_cached_failure_holds_no_frames(
            "_sw_abi_broken_tables3",
            """
            import weakref
            import _sw_abi_holder

            class Marker:
                pass

            def fail():
                marker = Marker()
                _sw_abi_holder.ref = weakref.ref(marker)
                import _sw_abi_no_such_dep3

            fail()
            """,
        )
        self.assertIn("No module named '_sw_abi_no_such_dep3'", text)

    def test_cached_failure_of_an_exception_that_formats_its_argument(self):
        # copy.copy() would rebuild this exception from its formatted args
        # and format them again; the cached text is the original message.
        text = self._assert_cached_failure_holds_no_frames(
            "_sw_abi_formatting_tables",
            """
            import weakref
            import _sw_abi_holder

            class TableError(Exception):
                def __init__(self, count):
                    super().__init__(f"{count} bad records")

            class Marker:
                pass

            def fail():
                marker = Marker()
                _sw_abi_holder.ref = weakref.ref(marker)
                raise TableError(3)

            fail()
            """,
        )
        self.assertIn("TableError: 3 bad records", text)
        self.assertNotIn("bad records bad records", text)

    def test_cached_failure_of_an_exception_nested_in_args(self):
        # The inner exception, carried in the outer one's args, has a
        # traceback into fail()'s frame.
        text = self._assert_cached_failure_holds_no_frames(
            "_sw_abi_nested_tables",
            """
            import weakref
            import _sw_abi_holder

            class Marker:
                pass

            def fail():
                marker = Marker()
                _sw_abi_holder.ref = weakref.ref(marker)
                raise KeyError("inner")

            try:
                fail()
            except KeyError as inner:
                raise RuntimeError(inner)
            """,
        )
        self.assertIn("KeyError: 'inner'", text)
        self.assertIn("RuntimeError", text)

    def test_concurrent_first_lookups_load_once(self):
        name = "_sw_abi_slow_tables"
        self._write_module(
            name,
            """
            import time
            time.sleep(0.2)
            from abi.fixtures import RECORDS
            """,
        )
        self._with_data_module(name)
        results: typing.List[typing.Any] = []
        barrier = threading.Barrier(8)

        def lookup():
            barrier.wait()
            try:
                results.append(abi.resolve(X86_64))
            except BaseException as e:  # pragma: no cover - reported below
                results.append(e)

        with mock.patch.object(
            registry.importlib, "import_module", wraps=importlib.import_module
        ) as import_module:
            threads = [threading.Thread(target=lookup) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(60)
        self.assertEqual(import_module.call_count, 1)
        self.assertEqual(len(results), 8)
        self.assertTrue(all(r is fixtures.X86_64_SYSV for r in results), results)

    def test_concurrent_failing_lookups_load_once(self):
        self._with_data_module("smallworld.platforms.abi._no_such_tables")
        errors: typing.List[BaseException] = []
        barrier = threading.Barrier(8)

        def lookup():
            barrier.wait()
            try:
                abi.resolve(X86_64)
            except abi.ABITablesUnavailable as e:
                errors.append(e)

        with mock.patch.object(
            registry.importlib, "import_module", wraps=importlib.import_module
        ) as import_module:
            threads = [threading.Thread(target=lookup) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(60)
        self.assertEqual(import_module.call_count, 1)
        self.assertEqual(len(errors), 8)

    def _write_module(self, name, source):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with open(os.path.join(tmp.name, name + ".py"), "w") as f:
            f.write(textwrap.dedent(source))
        sys.path.insert(0, tmp.name)
        self.addCleanup(sys.path.remove, tmp.name)
        self.addCleanup(sys.modules.pop, name, None)

    def test_broken_tables_chain_the_cause(self):
        self._write_module(
            "_sw_abi_broken_tables", "import _sw_abi_no_such_dependency\n"
        )
        self._with_data_module("_sw_abi_broken_tables")
        # The first failing lookup gets the original exception chain.
        with self.assertRaises(abi.ABITablesUnavailable) as ctx:
            abi.resolve(X86_64)
        self.assertIsInstance(ctx.exception.__cause__, ModuleNotFoundError)
        self.assertIn("failed to load", str(ctx.exception))
        self.assertFalse(abi.tables_available())

    def test_lookup_while_loading_raises_instead_of_deadlocking(self):
        # A data module that looks the tables up while it is being imported
        # gets ABITablesUnavailable, and the outer load still succeeds.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with open(os.path.join(tmp.name, "_sw_abi_reentrant_tables.py"), "w") as f:
            f.write(
                "from smallworld.platforms import abi\n"
                "INNER = abi.tables_available()\n"
                "from abi.fixtures import RECORDS\n"
            )
        out = _run_python(
            f"""
            import sys
            sys.path.insert(0, {tmp.name!r})
            from smallworld.platforms import abi
            from smallworld.platforms.abi import registry
            registry.DATA_MODULE = "_sw_abi_reentrant_tables"
            print(abi.tables_available(),
                  sys.modules["_sw_abi_reentrant_tables"].INNER)
            """,
            timeout=60,
        )
        self.assertEqual(out.split(), ["True", "False"])

    def test_tables_without_records_tuple(self):
        self._write_module("_sw_abi_listy_tables", "RECORDS = []\n")
        self._with_data_module("_sw_abi_listy_tables")
        with self.assertRaisesRegex(abi.ABITablesUnavailable, "RECORDS tuple"):
            abi.resolve(X86_64)

    def test_invalid_tables(self):
        self._write_module(
            "_sw_abi_duplicate_tables",
            """
            from abi.fixtures import X86_64_SYSV
            RECORDS = (X86_64_SYSV, X86_64_SYSV)
            """,
        )
        self._with_data_module("_sw_abi_duplicate_tables")
        with self.assertRaises(abi.ABITablesUnavailable) as ctx:
            abi.resolve(X86_64)
        self.assertIn("duplicate ABI record id", str(ctx.exception.__cause__))

    def test_data_module_seam_loads_records_lazily(self):
        # The fixture module has the generated module's shape.
        self._with_data_module("abi.fixtures")
        self.assertIsNone(registry._loaded)
        self.assertTrue(abi.tables_available())
        self.assertIsNotNone(registry._loaded)
        self.assertIs(abi.resolve(X86_64), fixtures.X86_64_SYSV)
        self.assertEqual(abi.all_records(), fixtures.RECORDS)

    def test_use_records_restores_previous(self):
        self._with_data_module("smallworld.platforms.abi._no_such_tables")
        with registry._use_records(fixtures.RECORDS):
            self.assertIs(abi.resolve(X86_64), fixtures.X86_64_SYSV)
            # tables_available() and table_features() describe DATA_MODULE,
            # not the test record set.
            self.assertFalse(abi.tables_available())
            self.assertEqual(abi.table_features(), frozenset())
            with registry._use_records(fixtures.RECORDS[:1]):
                self.assertEqual(abi.variants(AARCH64), ())
            self.assertEqual(abi.variants(AARCH64), ("aapcs64",))
        with self.assertRaises(abi.ABITablesUnavailable):
            abi.resolve(X86_64)

    def test_api_features_is_a_fixed_code_feature_set(self):
        self._with_data_module("abi.fixtures")
        self.assertIsInstance(abi.API_FEATURES, frozenset)
        self.assertEqual(abi.API_FEATURES, frozenset())
        self.assertIn("API_FEATURES", abi.__all__)
        # Reading it loads nothing; it does not describe the tables.
        self.assertIsNone(registry._loaded)
        self.assertTrue(abi.tables_available())
        self.assertEqual(abi.API_FEATURES, frozenset())

    def test_table_features(self):
        # No FEATURES in the data module: none.
        self._with_data_module("abi.fixtures")
        self.assertEqual(abi.table_features(), frozenset())

    def test_table_features_from_the_data_module(self):
        self._write_module(
            "_sw_abi_featured_tables",
            """
            from abi.fixtures import RECORDS
            FEATURES = ("variants", "syscall")
            """,
        )
        self._with_data_module("_sw_abi_featured_tables")
        self.assertEqual(abi.table_features(), frozenset({"variants", "syscall"}))

    def test_table_features_without_tables(self):
        self._with_data_module("smallworld.platforms.abi._no_such_tables")
        self.assertEqual(abi.table_features(), frozenset())

    def test_bad_features_make_the_tables_unavailable(self):
        self._write_module(
            "_sw_abi_bad_features",
            """
            from abi.fixtures import RECORDS
            FEATURES = ["variants"]
            """,
        )
        self._with_data_module("_sw_abi_bad_features")
        self.assertEqual(abi.table_features(), frozenset())
        with self.assertRaisesRegex(abi.ABITablesUnavailable, "FEATURES must be"):
            abi.resolve(X86_64)

    def test_registry_rejects_bad_record_sets(self):
        sysv = fixtures.X86_64_SYSV
        cases = {
            "duplicate ABI record id": (sysv, sysv),
            "duplicate ABI record key": (
                sysv,
                dataclasses.replace(sysv, id="X86_64/LITTLE:other"),
            ),
            "two default ABI records": (
                sysv,
                dataclasses.replace(
                    fixtures.X86_64_MS_X64, is_default=True, is_family_default=False
                ),
            ),
            "two SYSTEMV family defaults": (
                sysv,
                dataclasses.replace(fixtures.X86_64_MS_X64, abi=platforms.ABI.SYSTEMV),
            ),
            "family default with no ABI family": (dataclasses.replace(sysv, abi=None),),
        }
        for message, records in cases.items():
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, re.escape(message)):
                    registry._use_records(records).__enter__()
        with self.assertRaises(TypeError):
            registry._use_records(("not a record",)).__enter__()


class ABIResolveTests(FixtureTestCase):
    def test_resolve_defaults(self):
        self.assertIs(self.x86, fixtures.X86_64_SYSV)
        self.assertIs(abi.resolve(X86_64, None), fixtures.X86_64_SYSV)
        self.assertIs(abi.resolve(X86_64, platforms.ABI.SYSTEMV), self.x86)
        self.assertIs(self.win, fixtures.X86_64_MS_X64)
        # A variant alone selects that record, whatever its family.
        self.assertIs(abi.resolve(X86_64, variant="ms-x64"), self.win)
        self.assertIs(abi.resolve(X86_64, platforms.ABI.WINDOWS, "ms-x64"), self.win)
        self.assertIs(abi.resolve(X86_64, None, "ms-x64"), self.win)
        self.assertIs(abi.resolve(X86_64, variant="sysv"), self.x86)
        # The PE default goes through default_variant(container="pe").
        pe = abi.default_variant(X86_64, container="pe")
        self.assertIs(abi.resolve(X86_64, variant=pe), self.win)
        self.assertIs(abi.resolve(X86_64), abi.resolve(X86_64))

    def test_resolve_failures(self):
        with self.assertRaisesRegex(ValueError, "no ABI record 'nope'"):
            abi.resolve(X86_64, variant="nope")
        # An explicit family together with a variant must match.
        with self.assertRaisesRegex(
            ValueError, "belongs to the WINDOWS family, not the SYSTEMV family"
        ):
            abi.resolve(X86_64, platforms.ABI.SYSTEMV, "ms-x64")
        with self.assertRaisesRegex(ValueError, "no CDECL ABI record"):
            abi.resolve(X86_64, platforms.ABI.CDECL)
        with self.assertRaisesRegex(ValueError, "no NONE ABI record"):
            abi.resolve(X86_64, platforms.ABI.NONE)
        mips = platforms.Platform(
            platforms.Architecture.MIPS32, platforms.Byteorder.BIG
        )
        with self.assertRaisesRegex(ValueError, "no default ABI record"):
            abi.resolve(mips, None)

    def test_abi_must_be_an_abi_member(self):
        for call in (abi.resolve, abi.maybe_resolve):
            with self.subTest(call=call.__name__):
                with self.assertRaisesRegex(TypeError, "must be an ABI member"):
                    call(X86_64, "systemv")  # type: ignore[arg-type]
                with self.assertRaisesRegex(TypeError, "must be an ABI member"):
                    call(X86_64, "windows", "ms-x64")  # type: ignore[arg-type]

    def test_maybe_resolve_is_tri_state(self):
        self.assertIs(abi.maybe_resolve(X86_64), self.x86)
        self.assertIsNone(abi.maybe_resolve(X86_64, platforms.ABI.CDECL))
        self.assertIsNone(abi.maybe_resolve(X86_64, variant="nope"))
        self.assertIsNone(abi.maybe_resolve(X86_64, platforms.ABI.SYSTEMV, "ms-x64"))
        mips = platforms.Platform(
            platforms.Architecture.MIPS32, platforms.Byteorder.BIG
        )
        self.assertIsNone(abi.maybe_resolve(mips))

    def test_familyless_variant(self):
        go = dataclasses.replace(
            fixtures.X86_64_SYSV,
            id="X86_64/LITTLE:go-abiinternal",
            variant="go-abiinternal",
            abi=None,
            is_default=False,
            is_family_default=False,
            per_function=True,
        )
        with registry._use_records(fixtures.RECORDS + (go,)):
            self.assertIs(abi.resolve(X86_64, variant="go-abiinternal"), go)
            self.assertIs(abi.resolve(X86_64), fixtures.X86_64_SYSV)
            with self.assertRaisesRegex(ValueError, "belongs to no ABI family"):
                abi.resolve(X86_64, platforms.ABI.SYSTEMV, "go-abiinternal")
            self.assertIsNone(
                abi.maybe_resolve(X86_64, platforms.ABI.SYSTEMV, "go-abiinternal")
            )

    def test_mechanics_for(self):
        self.assertIs(abi.mechanics_for(X86_64, platforms.ABI.NONE), self.x86)
        self.assertIs(abi.mechanics_for(X86_64, platforms.ABI.WINDOWS), self.win)

    def test_enumeration(self):
        self.assertEqual(abi.variants(X86_64), ("sysv", "ms-x64"))
        self.assertEqual(abi.variants(AARCH64), ("aapcs64",))
        mips = platforms.Platform(
            platforms.Architecture.MIPS32, platforms.Byteorder.BIG
        )
        self.assertEqual(abi.variants(mips), ())
        self.assertEqual(abi.all_records(), fixtures.RECORDS)
        self.assertEqual(abi.default_variant(X86_64), "sysv")
        self.assertEqual(abi.default_variant(X86_64, container="pe"), "ms-x64")
        with self.assertRaisesRegex(ValueError, "unknown container"):
            abi.default_variant(X86_64, container="macho")
        with self.assertRaisesRegex(ValueError, "no WINDOWS ABI record"):
            abi.default_variant(AARCH64, container="pe")

    def test_by_id(self):
        self.assertIs(abi.by_id("AARCH64/LITTLE:aapcs64"), self.a64)
        with self.assertRaisesRegex(ValueError, "no ABI record with id"):
            abi.by_id("AARCH64/LITTLE:nope")


# ---------------------------------------------------------------------------
# Query API semantics
# ---------------------------------------------------------------------------


class ABIArgumentReturnQueryTests(FixtureTestCase):
    def test_x86_64_arguments(self):
        self.assertEqual(
            self.x86.int_arg_registers(), ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
        )
        self.assertEqual(self.x86.pointer_arg_registers(), self.x86.int_arg_registers())
        self.assertEqual(
            self.x86.int_arg_registers(form="abi"),
            ("%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9"),
        )
        self.assertEqual(
            self.x86.fp_arg_registers(), tuple(f"xmm{i}" for i in range(8))
        )
        self.assertEqual(
            self.x86.fp_arg_registers(form="root"), tuple(f"ymm{i}" for i in range(8))
        )
        self.assertEqual(self.win.int_arg_registers(), ("rcx", "rdx", "r8", "r9"))
        self.assertEqual(self.win.fp_arg_registers(), ("xmm0", "xmm1", "xmm2", "xmm3"))

    def test_aarch64_arguments(self):
        self.assertEqual(self.a64.int_arg_registers(), tuple(f"x{i}" for i in range(8)))
        self.assertEqual(self.a64.fp_arg_registers(), tuple(f"q{i}" for i in range(8)))
        self.assertEqual(
            self.a64.fp_arg_registers("double"), tuple(f"d{i}" for i in range(8))
        )
        self.assertEqual(
            self.a64.fp_arg_registers("single"), tuple(f"s{i}" for i in range(8))
        )
        self.assertEqual(
            self.a64.fp_arg_registers("single", form="root"),
            tuple(f"q{i}" for i in range(8)),
        )
        self.assertEqual(
            self.a64.fp_arg_registers("double", pieces=True)[:2], (("d0",), ("d1",))
        )
        with self.assertRaises(ValueError):
            self.a64.fp_arg_registers("quad")

    def test_stack_only_and_soft_float(self):
        stack_only = dataclasses.replace(
            self.x86,
            int_args=dataclasses.replace(
                self.x86.int_args, registers=(), alloc=abi.IntAlloc.STACK_ONLY
            ),
            fp_args=None,
        )
        self.assertEqual(stack_only.int_arg_registers(), ())
        self.assertEqual(stack_only.pointer_arg_registers(), ())
        self.assertEqual(stack_only.fp_arg_registers(), ())
        self.assertEqual(stack_only.fp_arg_registers(pieces=True), ())

    def test_double_pairs(self):
        # MIPS o32 FR=0 shape: the allocation unit is a pair.
        a64 = self.a64
        q = {e.name: e for e in a64.fp_args.registers}
        pairs = ((q["q0"], q["q1"]), (q["q2"], q["q3"]))
        paired = dataclasses.replace(
            a64,
            fp_args=dataclasses.replace(
                a64.fp_args, double_view=(), double_pairs=pairs
            ),
        )
        self.assertEqual(paired.fp_arg_registers("double"), ("q0", "q2"))
        self.assertEqual(
            paired.fp_arg_registers("double", pieces=True),
            (("q0", "q1"), ("q2", "q3")),
        )
        self.assertEqual(paired.fp_arg_registers(), ("q0", "q2"))

    def test_returns(self):
        self.assertEqual(self.x86.int_return_registers(), ("rax", "rdx"))
        self.assertEqual(self.x86.pointer_return_registers(), ("rax", "rdx"))
        self.assertEqual(self.x86.primary_return_registers(), ("rax",))
        self.assertEqual(self.x86.fp_return_registers(), ("xmm0", "xmm1"))
        self.assertEqual(self.win.int_return_registers(), ("rax",))
        self.assertEqual(self.a64.int_return_registers(), ("x0", "x1"))
        self.assertEqual(self.a64.primary_return_registers(), ("x0",))

    def test_primary_return_adds_a_distinct_pointer_register(self):
        # m68k shape: d0 for integers, a0 for pointers.
        x86 = self.x86
        rdx = x86.returns.int_registers[1]
        rax = x86.returns.int_registers[0]
        # The pointer goes to rdx (a0) and is mirrored in rax (d0).
        m68k_like = dataclasses.replace(
            x86,
            returns=dataclasses.replace(
                x86.returns,
                int_registers=(rax,),
                pointer_registers=(rdx,),
                pointer_mirror=("rax",),
            ),
        )
        self.assertEqual(m68k_like.primary_return_registers(), ("rax", "rdx"))
        self.assertEqual(m68k_like.pointer_return_registers(), ("rdx",))
        self.assertEqual(m68k_like.returns.pointer_mirror, ("rax",))
        self.assertEqual(validate.check_record(m68k_like), ())
        self.assertEqual(self.x86.returns.pointer_mirror, ())

    def test_tricore_separate_pointer_class(self):
        tc = abi.resolve(fixtures.TRICORE)
        self.assertEqual(tc.int_arg_registers(), ("d4", "d5", "d6", "d7"))
        self.assertEqual(tc.pointer_arg_registers(), ("a4", "a5", "a6", "a7"))
        self.assertNotEqual(tc.pointer_arg_registers(), tc.int_arg_registers())
        self.assertEqual(tc.int_return_registers(), ("d2", "d3"))
        self.assertEqual(tc.pointer_return_registers(), ("a2",))
        self.assertEqual(tc.primary_return_registers(), ("d2", "a2"))
        # Callee-saved values come from both the data and the address file
        # (a10, the stack pointer, and a11, the link register, are not
        # values).
        self.assertEqual(
            tc.callee_saved_values(),
            tuple(f"d{i}" for i in range(8, 16)) + ("a12", "a13", "a14", "a15"),
        )
        self.assertTrue(tc.is_callee_saved_value("a12"))
        self.assertFalse(tc.is_callee_saved_value("a10"))
        self.assertFalse(tc.is_callee_saved_value("a11"))
        self.assertEqual(
            tc.callee_saved(klass=abi.RegClass.ADDRESS, names_only=True),
            ("a10", "a11", "a12", "a13", "a14", "a15"),
        )
        self.assertTrue(tc.is_stack_pointer("sp"))
        self.assertEqual(tc.link_register, "a11")
        self.assertTrue(tc.is_callee_saved("ra"))
        self.assertIs(tc.sret.arg_class, abi.RegClass.ADDRESS)

    def test_unknown_form(self):
        with self.assertRaises(ValueError):
            self.x86.int_arg_registers(form="ghidra")
        with self.assertRaises(ValueError):
            self.x86.callee_saved(names_only=True, form="ghidra")


class ABIPreservationQueryTests(FixtureTestCase):
    def test_callee_saved_values(self):
        # PR #150's X86_64 and AArch64 rows (register-file order).
        self.assertEqual(
            self.x86.callee_saved_values(),
            ("rbx", "r12", "r13", "r14", "r15", "rbp"),
        )
        self.assertEqual(
            set(self.win.callee_saved_values()),
            {"rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"},
        )
        self.assertEqual(
            self.a64.callee_saved_values(), tuple(f"x{i}" for i in range(19, 30))
        )

    def test_callee_saved_lists(self):
        self.assertEqual(
            self.x86.callee_saved(names_only=True),
            ("rbx", "r12", "r13", "r14", "r15", "rsp", "rbp", "fctrl"),
        )
        # mxcsr is only partly callee-saved: it is not a callee-saved root,
        # but its callee-saved entry is listed by name.
        self.assertNotIn(
            "mxcsr", self.x86.callee_saved(names_only=True, include_unmodeled=True)
        )
        self.assertEqual(
            self.x86.callee_saved(names_only=True, include_unmodeled=True, form="name")[
                -1
            ],
            "mxcsr",
        )
        entries = self.x86.callee_saved()
        self.assertTrue(all(isinstance(e, abi.RegEntry) for e in entries))
        self.assertEqual(
            self.x86.callee_saved(roles=abi.Role.VALUE, names_only=True),
            ("rbx", "r12", "r13", "r14", "r15", "rbp"),
        )
        self.assertEqual(
            self.x86.callee_saved(
                roles=("stack-pointer", "fp-control"), names_only=True
            ),
            ("rsp", "fctrl"),
        )
        self.assertEqual(
            self.x86.callee_saved(
                klass=abi.RegClass.INT, exclude=("ebp", "rsp"), names_only=True
            ),
            ("rbx", "r12", "r13", "r14", "r15"),
        )
        # A lone string is one name to exclude.
        self.assertEqual(
            self.x86.callee_saved(exclude="rbp", names_only=True),
            ("rbx", "r12", "r13", "r14", "r15", "rsp", "fctrl"),
        )
        self.assertEqual(
            self.x86.caller_saved(exclude="edi", names_only=True)[:3],
            ("rax", "rcx", "rdx"),
        )
        self.assertNotIn("rdi", self.x86.caller_saved(exclude="edi", names_only=True))
        self.assertEqual(
            self.a64.callee_saved(klass="vector", names_only=True, form="name"),
            tuple(f"d{i}" for i in range(8, 16)),
        )
        # q8..q15 are only partly callee-saved, so no vector root is.
        self.assertEqual(self.a64.callee_saved(klass="vector", names_only=True), ())
        # ms-x64: xmm6..15 are callee-saved, ymm6..15 as a whole are not.
        win_callee = self.win.callee_saved(klass="vector", names_only=True, form="name")
        self.assertEqual(win_callee, tuple(f"xmm{i}" for i in range(6, 16)))
        self.assertEqual(self.win.callee_saved(klass="vector", names_only=True), ())

    def test_root_lists_agree_with_preservation_of(self):
        kinds = abi.PreservationKind
        for record in fixtures.RECORDS:
            with self.subTest(record=record.id):
                callee = record.callee_saved(names_only=True, include_unmodeled=True)
                caller = record.caller_saved(names_only=True, include_unmodeled=True)
                self.assertFalse(set(callee) & set(caller))
                for root in record.preservation.universe:
                    kind = record.preservation_of(root)
                    self.assertEqual(root in callee, kind is kinds.CALLEE_SAVED, root)
                    self.assertEqual(root in caller, kind is kinds.CALLER_SAVED, root)
                    neither = root not in callee and root not in caller
                    self.assertEqual(neither, kind is kinds.NEITHER, root)
                    self.assertEqual(root in callee, record.is_callee_saved(root))
                    self.assertEqual(root in caller, record.is_caller_saved(root))
        # The AArch64 example: q8 is caller-saved, not callee-saved; its
        # preserved low half is listed by name.
        self.assertNotIn("q8", self.a64.callee_saved(names_only=True))
        self.assertIn("q8", self.a64.caller_saved(names_only=True))
        self.assertIn("d8", self.a64.callee_saved(names_only=True, form="name"))
        self.assertIn("v8.d[1]", self.a64.caller_saved(names_only=True, form="abi"))
        # ms-x64: ymm6..ymm15 are caller-saved roots.
        self.assertIn("ymm6", self.win.caller_saved(names_only=True))
        self.assertIn(
            "mxcsr", self.x86.caller_saved(names_only=True, include_unmodeled=True)
        )

    def test_caller_saved_lists(self):
        caller = self.a64.caller_saved(names_only=True)
        self.assertEqual(caller[:8], tuple(f"x{i}" for i in range(8)))
        self.assertIn("x30", caller)
        # q8's upper half is clobbered, so q8 is a caller-saved root.
        self.assertTrue(self.a64.is_caller_saved("q8"))
        self.assertIn("q8", caller)
        self.assertIn("q16", caller)
        self.assertNotIn("x19", caller)
        self.assertEqual(
            self.a64.caller_saved(roles=abi.Role.RESERVED, names_only=True),
            ("x16", "x17", "x18"),
        )
        self.assertEqual(
            [e.offset for e in self.a64.caller_saved() if e.root == "q8"], [8]
        )

    def test_partial_registers_aarch64(self):
        a64 = self.a64
        self.assertTrue(a64.is_callee_saved("d8"))
        self.assertTrue(a64.is_callee_saved("s8"))
        self.assertFalse(a64.is_callee_saved_value("d8"))
        self.assertFalse(a64.is_caller_saved("d8"))
        self.assertFalse(a64.is_callee_saved("q8"))
        self.assertTrue(a64.is_caller_saved("q8"))
        self.assertEqual(a64.preservation_of("d8"), abi.PreservationKind.CALLEE_SAVED)
        self.assertEqual(a64.preservation_of("q8"), abi.PreservationKind.CALLER_SAVED)
        self.assertTrue(a64.is_caller_saved("q16"))
        self.assertFalse(a64.is_callee_saved("d16"))

    def test_partial_registers_ms_x64(self):
        self.assertTrue(self.win.is_callee_saved("xmm6"))
        self.assertFalse(self.win.is_callee_saved("ymm6"))
        self.assertTrue(self.win.is_caller_saved("ymm6"))
        self.assertFalse(self.win.is_callee_saved("xmm5"))
        self.assertTrue(self.win.is_caller_saved("xmm5"))
        self.assertFalse(self.x86.is_callee_saved("xmm6"))

    def test_any_spelling(self):
        x86 = self.x86
        for name in ("rbx", "ebx", "bx", "bl", "bh", "%rbx"):
            with self.subTest(name=name):
                self.assertTrue(x86.is_callee_saved(name))
                self.assertTrue(x86.is_callee_saved_value(name))
                self.assertFalse(x86.is_caller_saved(name))
        self.assertTrue(x86.is_caller_saved("edi"))
        self.assertTrue(x86.is_caller_saved("al"))
        self.assertTrue(self.a64.is_callee_saved_value("w19"))
        self.assertTrue(self.a64.is_callee_saved_value("fp"))
        self.assertTrue(self.a64.is_caller_saved("lr"))

    def test_abi_aliases_and_case(self):
        a64 = self.a64
        # AAPCS64 IP0/IP1/PR, which the PlatformDef does not name.
        for name in ("ip0", "IP0", "ip1", "Ip1", "pr", "PR"):
            with self.subTest(name=name):
                self.assertTrue(a64.is_caller_saved(name))
                self.assertTrue(a64.is_reserved(name))
        self.assertEqual(
            a64.registers_with_role("linkage-scratch", form="root"), ("x16", "x17")
        )
        # Any spelling matches ignoring case.
        self.assertTrue(a64.is_callee_saved_value("X19"))
        self.assertTrue(a64.is_callee_saved_value("W19"))
        self.assertTrue(self.x86.is_callee_saved_value("EBX"))
        self.assertTrue(self.x86.is_callee_saved_value("%RBX"))
        self.assertEqual(
            self.x86.callee_saved(exclude="RBP", names_only=True)[-2:], ("rsp", "fctrl")
        )
        self.assertFalse(a64.is_caller_saved("ip2"))
        self.assertIsNone(a64.preservation_of("IPX"))

    def test_neither_and_not_values(self):
        x86 = self.x86
        # rsp is callee-saved but not a value; fsbase is neither.
        self.assertTrue(x86.is_callee_saved("rsp"))
        self.assertFalse(x86.is_callee_saved_value("rsp"))
        self.assertFalse(x86.is_callee_saved("fsbase"))
        self.assertFalse(x86.is_caller_saved("fsbase"))
        self.assertEqual(x86.preservation_of("fsbase"), abi.PreservationKind.NEITHER)
        a64 = self.a64
        self.assertFalse(a64.is_callee_saved("xzr"))
        self.assertFalse(a64.is_caller_saved("xzr"))
        self.assertFalse(a64.is_callee_saved_value("x30"))
        self.assertFalse(a64.is_callee_saved_value("sp"))

    def test_masked_control_register(self):
        # mxcsr: control bits callee-saved, status flags caller-saved.
        x86 = self.x86
        self.assertFalse(x86.is_callee_saved("mxcsr"))
        self.assertTrue(x86.is_caller_saved("mxcsr"))
        masks = [
            (e.preserved_mask, e.has_role("fp-control"))
            for e in x86.callee_saved(include_unmodeled=True)
            + x86.caller_saved(include_unmodeled=True)
            if e.name == "mxcsr"
        ]
        self.assertEqual(masks, [(0xFFC0, True), (0x003F, False)])

    def test_unknown_names_never_raise(self):
        for record in (self.x86, self.a64):
            for name in ("nope", "", "rip" if record is self.x86 else "pc", None, 5):
                with self.subTest(record=record.id, name=name):
                    self.assertFalse(record.is_callee_saved(name))
                    self.assertFalse(record.is_callee_saved_value(name))
                    self.assertFalse(record.is_caller_saved(name))
                    self.assertFalse(record.is_reserved(name))
                    self.assertIsNone(record.preservation_of(name))

    def test_not_caller_saved_is_not_callee_saved(self):
        # The documented asymmetry: neither is a third answer.
        for name in ("fsbase", "xzr"):
            record = self.x86 if name == "fsbase" else self.a64
            self.assertFalse(record.is_caller_saved(name))
            self.assertFalse(record.is_callee_saved(name))

    def test_reserved_and_roles(self):
        self.assertEqual(self.a64.reserved(), ("x16", "x17", "x18", "xzr"))
        self.assertTrue(self.a64.is_reserved("x18"))
        self.assertTrue(self.a64.is_reserved("w16"))
        self.assertTrue(self.a64.is_caller_saved("x18"))
        self.assertFalse(self.a64.is_reserved("x19"))
        self.assertEqual(self.x86.reserved(), ())
        self.assertEqual(
            self.a64.registers_with_role(abi.Role.LINKAGE_SCRATCH), ("x16", "x17")
        )
        self.assertEqual(self.a64.registers_with_role("tls"), ("tpidr_el0",))
        self.assertEqual(self.x86.registers_with_role("fp-control"), ("fctrl",))
        self.assertEqual(
            self.x86.registers_with_role("fp-control", include_unmodeled=True),
            ("fctrl", "mxcsr"),
        )


class ABISpecialRegisterQueryTests(FixtureTestCase):
    def test_x86_64(self):
        x86 = self.x86
        self.assertEqual(x86.stack_pointer, "rsp")
        self.assertTrue(x86.is_stack_pointer("esp"))
        self.assertFalse(x86.is_stack_pointer("rbp"))
        self.assertEqual(x86.frame_pointer, "rbp")
        self.assertEqual(x86.frame_pointer_for("x86"), "rbp")
        self.assertEqual(x86.frame_pointers(), ("rbp",))
        self.assertTrue(x86.is_frame_pointer("ebp"))
        self.assertIsNone(x86.link_register)
        self.assertIsNone(x86.global_pointer)
        self.assertEqual(x86.thread_pointer, "fsbase")
        self.assertEqual(x86.static_chain, "r10")
        self.assertEqual(x86.key, (X86_64, "sysv"))

    def test_aarch64(self):
        a64 = self.a64
        self.assertEqual(a64.stack_pointer, "sp")
        self.assertTrue(a64.is_stack_pointer("wsp"))
        self.assertEqual(a64.frame_pointer, "x29")
        self.assertTrue(a64.is_frame_pointer("fp"))
        self.assertEqual(a64.link_register, "x30")
        self.assertEqual(a64.thread_pointer, "tpidr_el0")
        self.assertIsNone(a64.static_chain)

    def test_frame_pointer_by_isa(self):
        # ARM shape: r11 in ARM state, r7 in Thumb.
        a64 = self.a64
        x7 = a64.int_args.registers[7]
        thumbish = dataclasses.replace(
            a64,
            special=dataclasses.replace(
                a64.special, frame_pointer_by_isa=(("thumb", x7),)
            ),
        )
        self.assertEqual(thumbish.frame_pointer_for("thumb"), "x7")
        self.assertEqual(thumbish.frame_pointer_for("arm"), "x29")
        self.assertEqual(thumbish.frame_pointers(), ("x29", "x7"))
        self.assertTrue(thumbish.is_frame_pointer("w7"))


# ---------------------------------------------------------------------------
# Immutability, identity, determinism, validation
# ---------------------------------------------------------------------------

_DUMP_SCRIPT = """
import sys
from abi import fixtures
from smallworld.platforms.abi import registry
out = []
with registry._use_records(fixtures.RECORDS):
    for d in registry.all_records():
        out.append(repr((
            d.id, d.int_arg_registers(), d.fp_arg_registers(),
            d.fp_arg_registers("double", pieces=True),
            d.int_return_registers(), d.primary_return_registers(),
            d.fp_return_registers(), d.callee_saved(names_only=True),
            d.caller_saved(names_only=True, include_unmodeled=True),
            d.callee_saved_values(), d.reserved(), d.preservation.universe,
            [e.roles for e in d.callee_saved(include_unmodeled=True)],
            [d.preservation_of(n) for n in ("ebx", "d8", "q8", "mxcsr", "nope")],
        )))
sys.stdout.write("\\n".join(out))
"""


class ABIRecordIdentityTests(FixtureTestCase):
    def test_records_are_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.x86.variant = "other"  # type: ignore[misc]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.x86.int_args.registers[0].name = "rax"  # type: ignore[misc]
        self.assertIsInstance(self.x86.int_arg_registers(), tuple)
        self.assertIsInstance(self.x86.callee_saved(), tuple)

    def test_equality_and_hash_by_id(self):
        clone = dataclasses.replace(self.x86, toolchain="clang")
        self.assertIsNot(clone, self.x86)
        self.assertEqual(clone, self.x86)
        self.assertEqual(hash(clone), hash(self.x86))
        self.assertNotEqual(self.x86, self.win)
        self.assertEqual(len({self.x86, clone, self.win}), 2)
        self.assertNotEqual(self.x86, "X86_64/LITTLE:sysv")
        self.assertEqual(repr(self.x86), "ABIDef('X86_64/LITTLE:sysv')")

    def test_pickle_and_copy_by_id(self):
        for record in fixtures.RECORDS:
            with self.subTest(record=record.id):
                for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
                    self.assertIs(pickle.loads(pickle.dumps(record, protocol)), record)
                self.assertIs(copy.copy(record), record)
                self.assertIs(copy.deepcopy(record), record)
                self.assertIs(copy.deepcopy({"abi": record})["abi"], record)
        # A pickle holds only the id, not the record's data.
        data = pickle.dumps(self.x86)
        self.assertIn(b"X86_64/LITTLE:sysv", data)
        self.assertNotIn(b"rdi", data)
        self.assertLess(len(data), 200)

    def test_only_registry_records_pickle_or_copy(self):
        modified = dataclasses.replace(self.x86, toolchain="clang")
        for operation in (pickle.dumps, copy.copy, copy.deepcopy):
            with self.subTest(operation=operation.__name__):
                with self.assertRaisesRegex(
                    TypeError, "not the registry record with that id"
                ):
                    operation(modified)
        # Outside the record set the registry does not know the id at all.
        with registry._use_records(fixtures.RECORDS[:1]):
            with self.assertRaisesRegex(TypeError, "not a registry record") as ctx:
                pickle.dumps(self.a64)
            self.assertIsInstance(ctx.exception.__cause__, ValueError)

    def test_unpickle_without_the_record_fails_clearly(self):
        data = pickle.dumps(self.a64)
        with registry._use_records(fixtures.RECORDS[:1]):
            with self.assertRaisesRegex(ValueError, "no ABI record with id"):
                pickle.loads(data)

    def test_deterministic_across_hash_seeds(self):
        outputs = {
            seed: _run_python(_DUMP_SCRIPT, env={"PYTHONHASHSEED": seed})
            for seed in ("0", "1", "4242")
        }
        self.assertEqual(len(set(outputs.values())), 1, outputs)
        self.assertIn("X86_64/LITTLE:sysv", outputs["0"])

    def test_query_results_are_repeatable(self):
        first = self.a64.callee_saved(names_only=True)
        self.assertIs(self.a64._partition(), self.a64._partition())
        self.assertEqual(first, self.a64.callee_saved(names_only=True))


def _with_alias(record, root, alias):
    """`record`'s partition with `alias` added to the entry for `root`."""
    p = record.preservation

    def add(entries):
        return tuple(
            (
                dataclasses.replace(e, abi_aliases=e.abi_aliases + (alias,))
                if e.root == root
                else e
            )
            for e in entries
        )

    return dataclasses.replace(
        p,
        callee_saved=add(p.callee_saved),
        caller_saved=add(p.caller_saved),
        neither=add(p.neither),
    )


class ABIValidationTests(unittest.TestCase):
    def test_fixtures_are_valid(self):
        self.assertEqual(validate.check_records(fixtures.RECORDS), ())

    def test_platform_default_is_the_systemv_family_default(self):
        # A default outside the SYSTEMV family (here, no family at all).
        records = (
            dataclasses.replace(
                fixtures.X86_64_SYSV, abi=None, is_family_default=False
            ),
            fixtures.X86_64_MS_X64,
        )
        problems = "\n".join(validate.check_records(records))
        self.assertIn("a platform default must be the SYSTEMV family default", problems)

    def test_systemv_family_default_is_the_platform_default(self):
        records = (
            dataclasses.replace(fixtures.X86_64_SYSV, is_default=False),
            dataclasses.replace(fixtures.X86_64_MS_X64, is_default=True),
        )
        problems = "\n".join(validate.check_records(records))
        self.assertIn("SYSTEMV family default must be the platform default", problems)

    def test_spelling_collisions_are_reported_once(self):
        a64 = fixtures.AARCH64_AAPCS64
        # x19's name and abi_name are both "x19", so it collides twice.
        record = dataclasses.replace(a64, preservation=_with_alias(a64, "x16", "x19"))
        problems = validate.check_record(record)
        self.assertEqual(
            sum("names both" in problem for problem in problems), 1, problems
        )

    def test_detects_problems(self):
        sysv = fixtures.X86_64_SYSV
        a64 = fixtures.AARCH64_AAPCS64
        p = sysv.preservation
        rbx = p.callee_saved[0]
        cases = {
            "id should be": dataclasses.replace(sysv, id="X86_64:sysv"),
            "roles must be sorted": dataclasses.replace(
                sysv,
                preservation=dataclasses.replace(
                    p,
                    callee_saved=p.callee_saved[:-3]
                    + (
                        dataclasses.replace(
                            p.callee_saved[-3],  # rbp
                            roles=(abi.Role.FRAME_POINTER, abi.Role.VALUE),
                        ),
                    )
                    + p.callee_saved[-2:],
                ),
            ),
            "overlap on rbx": dataclasses.replace(
                sysv,
                preservation=dataclasses.replace(p, neither=p.neither + (rbx,)),
            ),
            "not in register-file order": dataclasses.replace(
                sysv,
                preservation=dataclasses.replace(
                    p, callee_saved=tuple(reversed(p.callee_saved))
                ),
            ),
            "universe root 'rbx' has no entries": dataclasses.replace(
                sysv,
                preservation=dataclasses.replace(p, callee_saved=p.callee_saved[1:]),
            ),
            "q8 bytes [0, 8) are in no class": dataclasses.replace(
                a64,
                preservation=dataclasses.replace(
                    a64.preservation,
                    callee_saved=tuple(
                        e for e in a64.preservation.callee_saved if e.name != "d8"
                    ),
                ),
            ),
            "partial should be": dataclasses.replace(
                sysv,
                int_args=dataclasses.replace(
                    sysv.int_args,
                    registers=(dataclasses.replace(rbx, partial=True),),
                ),
            ),
            "is not a PlatformDef register": dataclasses.replace(
                sysv,
                int_args=dataclasses.replace(
                    sysv.int_args,
                    registers=(dataclasses.replace(rbx, name="rbq", root="rbq"),),
                ),
            ),
            "list is not immutable": dataclasses.replace(
                sysv,
                int_args=dataclasses.replace(
                    sysv.int_args, registers=list(sysv.int_args.registers)
                ),
            ),
            "stack.first_arg_offset 8 is less than the 40 bytes": dataclasses.replace(
                fixtures.X86_64_MS_X64,
                stack=dataclasses.replace(
                    fixtures.X86_64_MS_X64.stack, first_arg_offset=8
                ),
            ),
            "argument register rbx is not caller-saved": dataclasses.replace(
                sysv,
                int_args=dataclasses.replace(sysv.int_args, registers=(rbx,)),
            ),
            "abi_name 'r12' is the PlatformDef's r12 (r12 bytes [0, 8)), not rbx": dataclasses.replace(
                sysv,
                int_args=dataclasses.replace(
                    sysv.int_args,
                    registers=(dataclasses.replace(rbx, abi_name="r12"),),
                ),
            ),
            "'%rbx' names both rbx and r12": dataclasses.replace(
                sysv,
                preservation=dataclasses.replace(
                    p,
                    callee_saved=(rbx,)
                    + (dataclasses.replace(p.callee_saved[1], abi_name="%rbx"),)
                    + p.callee_saved[2:],
                ),
            ),
            "abi alias 'x19' is the PlatformDef's x19 (x19 bytes [0, 8)), not x16": dataclasses.replace(
                a64, preservation=_with_alias(a64, "x16", "x19")
            ),
            "abi alias 'X19' is the PlatformDef's x19 (x19 bytes [0, 8)), not x16": dataclasses.replace(
                a64, preservation=_with_alias(a64, "x16", "X19")
            ),
            # w16 is the low 4 bytes of x16: the same root, other bytes.
            "abi alias 'W16' is the PlatformDef's w16 (x16 bytes [0, 4)), not x16 bytes [0, 8)": dataclasses.replace(
                a64, preservation=_with_alias(a64, "x16", "W16")
            ),
            "abi_name 'q8' is the PlatformDef's q8 (q8 bytes [0, 16)), not q8 bytes [8, 16)": dataclasses.replace(
                a64,
                preservation=dataclasses.replace(
                    a64.preservation,
                    caller_saved=tuple(
                        (
                            dataclasses.replace(e, abi_name="q8")
                            if e.abi_name == "v8.d[1]"
                            else e
                        )
                        for e in a64.preservation.caller_saved
                    ),
                ),
            ),
            "is not a FloatEncoding": dataclasses.replace(
                sysv,
                returns=dataclasses.replace(
                    sysv.returns,
                    fp_named=(("x87-80", sysv.returns.fp_named[0][1]),),  # type: ignore[arg-type]
                ),
            ),
            "'IP0' names both x16 and x17": dataclasses.replace(
                a64, preservation=_with_alias(a64, "x17", "IP0")
            ),
            "is not a VaListKind": dataclasses.replace(
                sysv,
                varargs=dataclasses.replace(
                    sysv.varargs,
                    va_list=dataclasses.replace(
                        sysv.varargs.va_list, kind="struct"  # type: ignore[arg-type]
                    ),
                ),
            ),
            "pointer_mirror: nope is not a PlatformDef register": dataclasses.replace(
                sysv,
                returns=dataclasses.replace(
                    sysv.returns,
                    pointer_registers=sysv.returns.int_registers[:1],
                    pointer_mirror=("nope",),
                ),
            ),
            "there is no primary pointer return": dataclasses.replace(
                sysv,
                returns=dataclasses.replace(sysv.returns, pointer_mirror=("rdx",)),
            ),
            "preserved_mask must be None or a positive mask": dataclasses.replace(
                sysv,
                preservation=dataclasses.replace(
                    p,
                    callee_saved=(dataclasses.replace(rbx, preserved_mask=1 << 64),)
                    + p.callee_saved[1:],
                ),
            ),
        }
        for needle, record in cases.items():
            with self.subTest(needle=needle):
                problems = "\n".join(validate.check_record(record))
                self.assertIn(needle, problems)


class ABIMaskValidationTests(unittest.TestCase):
    """preserved_mask bits count from the entry's own offset."""

    def _with_mxcsr(self, *entries):
        sysv = fixtures.X86_64_SYSV
        p = sysv.preservation

        def keep(es):
            return tuple(e for e in es if e.root != "mxcsr")

        by_kind = {
            abi.PreservationKind.CALLEE_SAVED: [],
            abi.PreservationKind.CALLER_SAVED: [],
            abi.PreservationKind.NEITHER: [],
        }
        for kind, entry in entries:
            by_kind[kind].append(entry)
        return dataclasses.replace(
            sysv,
            preservation=dataclasses.replace(
                p,
                callee_saved=keep(p.callee_saved)
                + tuple(by_kind[abi.PreservationKind.CALLEE_SAVED]),
                caller_saved=keep(p.caller_saved)
                + tuple(by_kind[abi.PreservationKind.CALLER_SAVED]),
                neither=keep(p.neither) + tuple(by_kind[abi.PreservationKind.NEITHER]),
            ),
        )

    @staticmethod
    def _mxcsr(offset, width, mask):
        return dataclasses.replace(
            fixtures.unmodeled("mxcsr", 4, abi.RegClass.SPECIAL, mask=mask),
            offset=offset,
            abi_width=width,
        )

    def test_offset_entries_that_tile_the_bits_are_valid(self):
        record = self._with_mxcsr(
            (fixtures.CALLEE, self._mxcsr(0, 2, 0xFFC0)),
            (fixtures.CALLER, self._mxcsr(0, 2, 0x003F)),
            (fixtures.NEITHER, self._mxcsr(2, 2, None)),
        )
        self.assertEqual(validate.check_record(record), ())

    def test_masked_entries_share_their_bytes(self):
        # Masks count from each entry's own value, so masked entries over
        # different bytes cannot be compared whatever the byte order.
        record = self._with_mxcsr(
            (fixtures.CALLEE, self._mxcsr(0, 2, 0xFF00)),
            (fixtures.CALLER, self._mxcsr(0, 2, 0x00FF)),
            (fixtures.NEITHER, self._mxcsr(1, 1, 0x0F)),
            (fixtures.NEITHER, self._mxcsr(2, 2, None)),
        )
        problems = "\n".join(validate.check_record(record))
        self.assertIn(
            "masked entries of mxcsr must share offset and abi_width", problems
        )

    def test_masks_of_one_value_must_be_disjoint(self):
        record = self._with_mxcsr(
            (fixtures.CALLEE, self._mxcsr(0, 4, 0xFFC0)),
            (fixtures.CALLER, self._mxcsr(0, 4, 0x00FF)),
            (fixtures.NEITHER, self._mxcsr(0, 4, 0xFFFF0000)),
        )
        problems = "\n".join(validate.check_record(record))
        self.assertIn(
            "callee_saved mxcsr and caller_saved mxcsr overlap on mxcsr", problems
        )

    def test_a_masked_value_and_an_unmasked_entry_must_not_overlap(self):
        record = self._with_mxcsr(
            (fixtures.CALLEE, self._mxcsr(0, 2, 0xFFC0)),
            (fixtures.CALLER, self._mxcsr(0, 2, 0x003F)),
            (fixtures.NEITHER, self._mxcsr(1, 3, None)),
        )
        problems = "\n".join(validate.check_record(record))
        self.assertIn("neither mxcsr and masked mxcsr overlap on mxcsr", problems)

    def test_every_bit_of_a_masked_root_has_a_class(self):
        record = self._with_mxcsr(
            (fixtures.CALLEE, self._mxcsr(0, 4, 0xFFC0)),
            (fixtures.CALLER, self._mxcsr(0, 4, 0x003F)),
        )
        problems = "\n".join(validate.check_record(record))
        self.assertIn("mxcsr bits 0xffff0000 are in no class", problems)


class ABIEnumAndFeatureTests(unittest.TestCase):
    def test_schema_enum_changes(self):
        self.assertFalse(hasattr(abi, "DerivedRole"))
        self.assertEqual(abi.RegClass.ADDRESS, "address")
        self.assertEqual(abi.SyscallErrorConvention.MIPS_A3_FLAG.value, "mips-a3-flag")
        self.assertEqual(abi.VaListKind.STRUCT, "struct")
        self.assertEqual(abi.EntryCondition.GLOBAL_ENTRY, "global-entry")
        self.assertEqual(abi.UnknownTypePolicy.SEXT32, "sext32")
        self.assertEqual(abi.StackPointerTarget.ARGC, "argc")

    def test_new_abi_members(self):
        ABI = platforms.ABI
        self.assertEqual(ABI.WINDOWS.value, "windows")
        self.assertEqual(ABI.STDCALL.value, "stdcall")
        self.assertEqual(ABI.THISCALL.value, "thiscall")
        self.assertFalse(hasattr(ABI, "DARWIN"))
        for member in ABI:
            self.assertRegex(member.name, r"^[A-Z]+$")
            self.assertRegex(member.value, r"^[a-z]+(-[a-z]+)*$")

    def test_schema_enums_are_kebab_case_strings(self):
        for name in abi.enums.__all__:
            enum_type = getattr(abi.enums, name)
            if not isinstance(enum_type, type):
                continue
            for member in enum_type:
                self.assertIsInstance(member, str)
                self.assertRegex(member.value, r"^[a-z0-9]+(-[a-z0-9]+)*$")

    def test_schema_enums_print_as_their_value(self):
        # Plain (str, Enum) formats differently on 3.9 and 3.11+.
        self.assertEqual(f"{abi.Role.FP_VALUE}", "fp-value")
        self.assertEqual(str(abi.Role.FP_VALUE), "fp-value")
        self.assertEqual(f"{abi.RegClass.INT:>4}", " int")
        self.assertEqual(repr(abi.Role.VALUE), "<Role.VALUE: 'value'>")

    def test_errors_are_configuration_errors(self):
        for error in (
            abi.UnrealizableLocation,
            abi.UnsupportedSignature,
            abi.ABITablesUnavailable,
        ):
            self.assertTrue(issubclass(error, exceptions.ConfigurationError))


class PlatformDefForPlatformTests(unittest.TestCase):
    def test_miss_chains_the_cause(self):
        platform = platforms.Platform(
            platforms.Architecture.LOONGARCH32, platforms.Byteorder.LITTLE
        )
        for _ in range(2):  # the second call is a memoized miss
            with self.assertRaisesRegex(ValueError, "No platform definition") as ctx:
                platforms.PlatformDef.for_platform(platform)
            self.assertIsInstance(ctx.exception.__cause__, ValueError)

    def test_any_failure_is_a_chained_value_error(self):
        # The historical contract: whatever goes wrong surfaces as ValueError.
        platform = platforms.Platform(
            platforms.Architecture.AARCH64, platforms.Byteorder.LITTLE
        )
        boom = RuntimeError("constructor failed")
        with mock.patch.object(utils, "find_subclass", side_effect=boom):
            with self.assertRaisesRegex(ValueError, "No platform definition") as ctx:
                platforms.PlatformDef.for_platform(platform)
        self.assertIs(ctx.exception.__cause__, boom)
        # KeyboardInterrupt is not an Exception and is not converted.
        with mock.patch.object(utils, "find_subclass", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                platforms.PlatformDef.for_platform(platform)

    def test_returns_a_fresh_instance_per_call(self):
        # magrathea's _pdef relies on getting its own instance.
        platform = platforms.Platform(
            platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
        )
        first = platforms.PlatformDef.for_platform(platform)
        second = platforms.PlatformDef.for_platform(platform)
        self.assertIsNot(first, second)
        self.assertIs(type(first), type(second))

    def test_hit_is_memoized(self):
        platform = platforms.Platform(
            platforms.Architecture.AARCH64, platforms.Byteorder.LITTLE
        )
        first = platforms.PlatformDef.for_platform(platform)
        key = (platforms.PlatformDef, (platform.architecture, platform.byteorder))
        self.assertIs(utils._SUBCLASS_CACHE[key], type(first))
        self.assertIs(type(platforms.PlatformDef.for_platform(platform)), type(first))

    def test_subclass_defined_after_a_miss_is_found(self):
        # In a subprocess, so the throwaway PlatformDef does not leak into
        # other tests that enumerate PlatformDef subclasses.
        out = _run_python("""
            from smallworld import platforms
            from smallworld.platforms.defs import AMD64
            p = platforms.Platform(
                platforms.Architecture.LOONGARCH32, platforms.Byteorder.BIG
            )
            try:
                platforms.PlatformDef.for_platform(p)
            except ValueError:
                pass
            class Late(AMD64):
                architecture = p.architecture
                byteorder = p.byteorder
            print(type(platforms.PlatformDef.for_platform(p)).__name__)
            """)
        self.assertEqual(out.strip(), "Late")


__all__ = [
    "ABIArgumentReturnQueryTests",
    "ABIEnumAndFeatureTests",
    "ABIImportGraphTests",
    "ABIMaskValidationTests",
    "ABIPreservationQueryTests",
    "ABIRecordIdentityTests",
    "ABIRegistryLoaderTests",
    "ABIResolveTests",
    "ABISpecialRegisterQueryTests",
    "ABIValidationTests",
    "PlatformDefForPlatformTests",
]


if __name__ == "__main__":
    unittest.main()
