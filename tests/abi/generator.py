"""Tests for the build-time ABI generator (tools/abi).

The tests that dump the dependencies need pypcode, angr and archinfo in this
interpreter (the dev environment and the nix devshell have them); they skip
elsewhere, for example on Python 3.9. The rest, including the no-data marker,
the import blocker and the emitter, run everywhere.
"""

import dataclasses
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import typing
import unittest
from unittest import mock

import smallworld
from smallworld.platforms import abi
from smallworld.platforms.abi import registry

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS_DIR = os.path.dirname(HERE)
ROOT = os.path.dirname(TESTS_DIR)
TOOLS = os.path.join(ROOT, "tools", "abi")
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

import emit  # noqa: E402
import generate  # noqa: E402
import stage1  # noqa: E402
import stage2  # noqa: E402
import stub_loader  # noqa: E402
from abi import fixtures  # noqa: E402
from common import GeneratorError  # noqa: E402
from overlay import RECORDS as SPECS  # noqa: E402
from overlay import versions  # noqa: E402
from overlay.x86 import PASSING as PSABI_CITE  # noqa: E402

DATA_REL = os.path.join("smallworld", "platforms", "abi", "_data")
SYSV_ID = "X86_64/LITTLE:sysv"


def _dependencies_importable() -> bool:
    return all(
        importlib.util.find_spec(name) is not None
        for name in ("pypcode", "angr", "archinfo")
    )


def _run(
    args: typing.List[str], env: typing.Optional[dict] = None
) -> subprocess.CompletedProcess:
    full_env = dict(os.environ)
    full_env.update(env or {})
    return subprocess.run(
        [sys.executable] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        env=full_env,
        timeout=600,
    )


def _tree(directory: str) -> typing.Dict[str, bytes]:
    out = {}
    for name in sorted(os.listdir(directory)):
        with open(os.path.join(directory, name), "rb") as fh:
            out[name] = fh.read()
    return out


class _Snapshot:
    """One stage-1 snapshot, dumped once per test run."""

    path: typing.Optional[str] = None
    data: typing.Optional[dict] = None
    _dir: typing.Optional[tempfile.TemporaryDirectory] = None

    @classmethod
    def get(cls) -> dict:
        if cls.data is None:
            cls._dir = tempfile.TemporaryDirectory(prefix="abi-snapshot-")
            cls.path = os.path.join(cls._dir.name, "snapshot.json")
            # Stage 1 as generate.py runs it: with a private TMPDIR.
            private = tempfile.mkdtemp(prefix="stage1-tmp-", dir=cls._dir.name)
            proc = _run(
                [os.path.join(TOOLS, "stage1.py"), "--out", cls.path],
                env=generate.stage1_environment(private),
            )
            if proc.returncode != 0:
                raise AssertionError(f"stage 1 failed:\n{proc.stderr}")
            with open(cls.path) as fh:
                cls.data = json.load(fh)
        return cls.data


def _sw() -> stub_loader.Smallworld:
    return stub_loader.from_modules("smallworld")


@unittest.skipUnless(_dependencies_importable(), "needs pypcode, angr and archinfo")
class ABIGeneratorTests(unittest.TestCase):
    """The generator end to end, on the dependencies installed here."""

    @classmethod
    def setUpClass(cls):
        cls.snapshot = _Snapshot.get()
        cls.result = stage2.build(cls.snapshot, _sw())
        cls.record = cls.result.records[0]

    def _build(self, specs, **kwargs):
        return stage2.build(self.snapshot, _sw(), specs=specs, **kwargs)

    def _spec(self, **changes):
        return dataclasses.replace(SPECS[0], **changes)

    def test_snapshot_is_from_a_supported_set(self):
        v = self.snapshot["versions"]
        versions.find(v["pypcode"], v["angr"], v["archinfo"])

    def test_generated_records_validate(self):
        self.assertEqual([r.id for r in self.result.records], [SYSV_ID])
        self.assertEqual(abi.validate.check_records(self.result.records), ())

    def test_equivalent_to_calling_context(self):
        from smallworld.state.models.amd64.systemv.systemv import (
            AMD64SysVCallingContext as ctx,
        )

        record = self.record
        self.assertEqual(record.int_arg_registers(), tuple(ctx._eight_byte_arg_regs))
        self.assertEqual(record.fp_arg_registers(), tuple(ctx._float_arg_regs))
        self.assertEqual(record.fp_arg_registers("double"), tuple(ctx._double_arg_regs))
        # the context writes 8-byte results to rax and FP results to xmm0
        self.assertEqual(record.primary_return_registers(), ("rax",))
        self.assertEqual(record.fp_return_registers()[0], "xmm0")
        self.assertEqual(record.stack.first_arg_offset, ctx._init_stack_offset)
        self.assertEqual(record.platform, ctx.platform)
        self.assertIs(record.abi, ctx.abi)

    def test_matches_the_hand_fixture(self):
        # The SW-01a fixture was transcribed from the psABI. The generated
        # record equals it field for field, except the psABI spellings the
        # fixture abbreviates (ymm0 for %ymm0, st0 for %st(0)), the record's
        # confidence (capped by its master-seed entries) and its sources.
        def normalize(value):
            if isinstance(value, abi.RegEntry):
                spelled = re.sub(r"[%()]", "", value.abi_name)
                return dataclasses.replace(value, abi_name=spelled)
            if dataclasses.is_dataclass(value) and not isinstance(value, type):
                changes = {
                    f.name: normalize(getattr(value, f.name))
                    for f in dataclasses.fields(value)
                }
                return type(value)(**changes)
            if isinstance(value, tuple):
                return tuple(normalize(v) for v in value)
            return value

        skip = {"confidence", "sources"}
        for field in dataclasses.fields(abi.ABIDef):
            if field.name in skip:
                continue
            with self.subTest(field=field.name):
                self.assertEqual(
                    emit.fingerprint(normalize(getattr(self.record, field.name))),
                    emit.fingerprint(
                        normalize(getattr(fixtures.X86_64_SYSV, field.name))
                    ),
                )

    def test_expectations_catch_a_wrong_generated_value(self):
        wrong = [
            dataclasses.replace(e, value="rsi") if e.field == "sret.register" else e
            for e in SPECS[0].expectations
        ]
        spec = self._spec(expectations=tuple(wrong))
        with self.assertRaisesRegex(
            GeneratorError, "sret.register is generated as 'rdi'"
        ):
            self._build([spec])

    def test_probe_oracles_cover_single_source_fields(self):
        # angr's own calling-convention code, asked by stage 1, cross-checks
        # the sret register and the stack slots Ghidra provides.
        probes = self.snapshot["angr"]["conventions"][SPECS[0].angr.key]["probes"]
        self.assertEqual(probes["sret_register"], "rdi")
        self.assertEqual(probes["stack_int_offsets"], [8, 16, 24])
        snapshot = json.loads(json.dumps(self.snapshot))
        snapshot["angr"]["conventions"][SPECS[0].angr.key]["probes"][
            "sret_register"
        ] = "rsi"
        with self.assertRaisesRegex(
            GeneratorError, "angr .* says .*sret.register is 'rsi'"
        ):
            stage2.build(snapshot, _sw())

    def test_oracle_ack_pins_the_disagreement(self):
        ack = dataclasses.replace(SPECS[0].oracle_acks[0], oracle=12)
        with self.assertRaisesRegex(GeneratorError, "but now it is 10 against 16"):
            self._build([self._spec(oracle_acks=(ack,))])

    def test_oracle_acks_are_unique_and_belong_to_their_record(self):
        ack = SPECS[0].oracle_acks[0]
        with self.assertRaisesRegex(GeneratorError, "is used by both"):
            self._build([self._spec(oracle_acks=(ack, ack))])
        foreign = dataclasses.replace(
            ack, field_pattern="*:data_model.sizes.long_double"
        )
        with self.assertRaisesRegex(GeneratorError, "must name its own record"):
            self._build([self._spec(oracle_acks=(foreign,))])

    def test_deviation_needs_an_observed_version(self):
        deviation = dataclasses.replace(SPECS[0].deviations[0], observed={})
        with self.assertRaisesRegex(GeneratorError, "observed is empty"):
            self._build([self._spec(deviations=(deviation,))])

    def test_record_confidence_must_be_a_confidence(self):
        hand = dict(SPECS[0].hand)
        hand["confidence"] = dataclasses.replace(hand["confidence"], value="hgih")
        with self.assertRaisesRegex(GeneratorError, "confidence 'hgih' is not one of"):
            self._build([self._spec(hand=hand)])

    def test_silent_oracles(self):
        # An oracle that says nothing about an acknowledged field is an error;
        # about any other field, a counted note in the report.
        snapshot = json.loads(json.dumps(self.snapshot))
        data = snapshot["ghidra"]["prototypes"][SPECS[0].ghidra.key][
            "data_organization"
        ]
        del data["wchar_size"]
        result = stage2.build(snapshot, _sw())
        self.assertIn("oracle notes (an oracle gave no answer): 1", result.report)
        del data["long_double_size"]
        with self.assertRaisesRegex(
            GeneratorError, "gives no value for .*long_double, which ACK-GH"
        ):
            stage2.build(snapshot, _sw())

    def test_silent_oracle_respects_ack_versions(self):
        # A 12.1-only ack does not make 11.4.2's silence an error (and the
        # other way round): the silence is a note under the other version.
        ack = SPECS[0].oracle_acks[0]
        snapshot = json.loads(json.dumps(self.snapshot))
        data = snapshot["ghidra"]["prototypes"][SPECS[0].ghidra.key][
            "data_organization"
        ]
        del data["long_double_size"]
        current = snapshot["versions"]["ghidra"]
        other = next(v for v in ("12.1", "11.4.2") if v != current)
        spec = self._spec(oracle_acks=(dataclasses.replace(ack, versions=(other,)),))
        result = stage2.build(snapshot, _sw(), specs=[spec])
        self.assertIn("oracle notes (an oracle gave no answer): 1", result.report)
        spec = self._spec(oracle_acks=(dataclasses.replace(ack, versions=(current,)),))
        with self.assertRaisesRegex(GeneratorError, "gives no value for"):
            stage2.build(snapshot, _sw(), specs=[spec])

    def test_deviation_ids_are_unique(self):
        deviation = SPECS[0].deviations[0]
        twin = dataclasses.replace(deviation, field="sret.register")
        with self.assertRaisesRegex(GeneratorError, "deviation id .* is used by both"):
            self._build([self._spec(deviations=(deviation, twin))])

    def test_expectation_on_a_missing_value_fails(self):
        snapshot = json.loads(json.dumps(self.snapshot))
        snapshot["angr"]["conventions"][SPECS[0].angr.key]["syscall_cc"] = None
        with self.assertRaisesRegex(
            GeneratorError, "syscall.number_register was not generated, but the overlay"
        ):
            stage2.build(snapshot, _sw())

    def test_stale_tables_still_load_when_warnings_are_errors(self):
        import warnings

        with tempfile.TemporaryDirectory() as tmp:
            text = emit.module("Stale test records.", [("X", fixtures.X86_64_SYSV)])
            text += "AVAILABLE = True\nRECORDS = (X,)\nSTALE = 'the overlay changed'\n"
            with open(os.path.join(tmp, "__init__.py"), "w") as fh:
                fh.write(text)
            module = stub_loader.mount_data_package("smallworld", tmp, "_sw_abi_werr")
            self.addCleanup(sys.modules.pop, module.__name__, None)
            stderr = io.StringIO()
            with warnings.catch_warnings(), mock.patch("sys.stderr", stderr):
                warnings.simplefilter("error", abi.ABITablesStale)
                tables = registry._load(module.__name__)
            self.addCleanup(setattr, registry, "_stale_reason", None)
            self.assertNotIsInstance(tables, str)
            self.assertEqual([r.id for r in tables.records], [SYSV_ID])
            # ... with a signal on stderr, and the reason kept
            self.assertIn("ABITablesStale (loaded anyway)", stderr.getvalue())
            self.assertIn("the overlay changed", registry._stale_reason)

    def test_missing_probe_results_are_problems(self):
        snapshot = json.loads(json.dumps(self.snapshot))
        snapshot["angr"]["conventions"][SPECS[0].angr.key]["probes"] = {
            "sret_register": None,
            "stack_int_offsets": [],
        }
        with self.assertRaises(GeneratorError) as caught:
            stage2.build(snapshot, _sw())
        self.assertIn("struct-return probe gave no register", str(caught.exception))
        self.assertIn("stack-argument probe gave []", str(caught.exception))

    def test_a_built_record_is_checked_in_full_despite_problems(self):
        # A problem found after the record was built (an unknown field) does
        # not stop the oracle comparison: both are reported in one run.
        hand = dict(SPECS[0].hand)
        hand["stack.bogus"] = hand["stack.red_zone"]
        snapshot = json.loads(json.dumps(self.snapshot))
        snapshot["angr"]["conventions"][SPECS[0].angr.key]["probes"][
            "sret_register"
        ] = "rsi"
        with self.assertRaises(GeneratorError) as caught:
            stage2.build(snapshot, _sw(), specs=[self._spec(hand=hand)])
        message = str(caught.exception)
        self.assertIn("stack.bogus, which is not a field", message)
        self.assertIn("unacknowledged oracle disagreement", message)

    def test_if_stale_notices_edited_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "_data")
            generate.generate(out, ROOT)
            self.assertTrue(generate.is_fresh(out, ROOT))
            with open(os.path.join(out, "x86.py"), "a") as fh:
                fh.write("# edited by hand\n")
            self.assertFalse(generate.is_fresh(out, ROOT))

    def test_keyed_deviation_is_independent_of_the_build_set(self):
        deviation = dataclasses.replace(
            SPECS[0].deviations[0], keying=True, versions=">=11.0"
        )
        record = self._build([self._spec(deviations=(deviation,))]).records[0]
        (keying,) = record.sources.ghidra_keying
        self.assertEqual(
            json.loads(keying.ghidra_value),
            {v: list(o) for v, o in sorted(deviation.observed.items())},
        )
        self.assertEqual(keying.versions, ">=11.0")

    def test_a_failed_record_does_not_report_stale_acks(self):
        hand = {k: v for k, v in SPECS[0].hand.items() if k != "stack.red_zone"}
        broken_id = "X86_64/LITTLE:broken"
        broken = self._spec(
            id=broken_id,
            variant="broken",
            hand=hand,
            deviations=tuple(
                dataclasses.replace(d, record=broken_id) for d in SPECS[0].deviations
            ),
        )
        with self.assertRaises(GeneratorError) as caught:
            self._build([broken])
        message = str(caught.exception)
        self.assertIn("no value for stack.red_zone", message)
        self.assertNotIn("stale oracle ack", message)

    def test_mutated_cspec_is_refused(self):
        import pypcode

        found = versions.find(
            *(self.snapshot["versions"][k] for k in ("pypcode", "angr", "archinfo"))
        )
        real = pypcode.ArchLanguage.from_id(SPECS[0].ghidra.language)
        with tempfile.TemporaryDirectory() as tmp:
            processors = os.path.join(os.path.dirname(pypcode.__file__), "processors")
            rel = os.path.relpath(real.archdir, processors)
            archdir = os.path.join(tmp, "processors", rel)
            os.makedirs(archdir)
            # copyfile, not copytree: the source may be a read-only store
            for name in ("x86-64-gcc.cspec", "x86.ldefs", "x86-64.sla"):
                shutil.copyfile(
                    os.path.join(real.archdir, name), os.path.join(archdir, name)
                )
            cspec = os.path.join(archdir, "x86-64-gcc.cspec")
            with open(cspec, "a") as fh:
                fh.write("<!-- mutated -->\n")

            class Language:
                def __init__(self):
                    self.archdir = archdir
                    self.ldef = real.ldef
                    self.slafile_path = os.path.join(archdir, "x86-64.sla")

            with (
                mock.patch.object(
                    pypcode.ArchLanguage, "from_id", return_value=Language()
                ),
                mock.patch.object(
                    pypcode, "__file__", os.path.join(tmp, "__init__.py")
                ),
                mock.patch.object(
                    stage1,
                    "_ldefs_path",
                    return_value=os.path.join(archdir, "x86.ldefs"),
                ),
            ):
                stderr = io.StringIO()
                with mock.patch("sys.stderr", stderr), self.assertRaises(SystemExit):
                    stage1.ghidra_snapshot(pypcode, found)
        self.assertIn("x86-64-gcc.cspec has SHA-256", stderr.getvalue())
        self.assertIn("pins", stderr.getvalue())

    def test_stage1_gets_a_private_tmpdir(self):
        seen = {}

        def fake_run(step, command, env=None):
            if "stage1.py" in " ".join(command):
                tmpdir = env["TMPDIR"]
                seen["tmpdir"] = tmpdir
                seen["mode"] = os.stat(tmpdir).st_mode & 0o777
                seen["same"] = env["TEMP"] == env["TMP"] == tmpdir
            raise GeneratorError("stop here")

        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(generate, "_run", fake_run),
            mock.patch.dict(os.environ, {"TMPDIR": tmp}),
        ):
            with self.assertRaises(GeneratorError):
                generate.generate(os.path.join(tmp, "out", "_data"), ROOT)
        self.assertEqual(seen["mode"], 0o700)
        self.assertTrue(seen["same"])
        self.assertNotEqual(os.path.realpath(seen["tmpdir"]), os.path.realpath(tmp))
        self.assertFalse(os.path.exists(seen["tmpdir"]))

    def test_planted_pyvex_cache_is_never_loaded(self):
        # pyvex unpickles $TMPDIR/pyvex_ffi_parser_cache.<user>.<md5>; plant a
        # malicious one in the TMPDIR the build inherits, and check stage 1
        # never reads it.
        import getpass
        import hashlib
        import pickle

        spec = importlib.util.find_spec("pyvex")
        vex_ffi = os.path.join(os.path.dirname(spec.origin), "vex_ffi.py")
        namespace: dict = {}
        with open(vex_ffi) as fh:
            exec(compile(fh.read(), vex_ffi, "exec"), namespace)
        digest = hashlib.md5(namespace["ffi_str"].encode("utf-8")).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "pwned")

            class Payload:
                def __reduce__(self):
                    return (os.mkdir, (marker,))

            cache = os.path.join(
                tmp, f"pyvex_ffi_parser_cache.{getpass.getuser()}.{digest}"
            )
            with open(cache, "wb") as fh:
                fh.write(pickle.dumps(Payload()))
            with mock.patch.dict(os.environ, {"TMPDIR": tmp, "TEMP": tmp, "TMP": tmp}):
                generate.generate(os.path.join(tmp, "out", "_data"), ROOT)
            self.assertFalse(os.path.exists(marker), "stage 1 loaded the planted cache")

    def test_generated_modules_are_black_stable(self):
        try:
            import black
        except ImportError:
            self.skipTest("black is not installed")
        for name, text in stage2.package_files(
            self.result, self.snapshot, ROOT
        ).items():
            self.assertEqual(black.format_str(text, mode=black.Mode()), text, name)

    def test_tables_declare_their_features(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage2.write_package(
                tmp, stage2.package_files(self.result, self.snapshot, ROOT)
            )
            module = stub_loader.mount_data_package(
                "smallworld", tmp, "_sw_abi_features"
            )
            self.addCleanup(sys.modules.pop, module.__name__, None)
            self.assertEqual(module.FEATURES, ("x86-64-sysv",))
            self.assertEqual(module.RECORDS[0].id, SYSV_ID)
        if abi.tables_available():
            self.assertIn("x86-64-sysv", abi.table_features())

    def test_every_mxcsr_bit_has_one_class(self):
        masks = {
            kind: [
                e.preserved_mask
                for e in getattr(self.record.preservation, kind)
                if e.root == "mxcsr"
            ]
            for kind in ("callee_saved", "caller_saved", "neither")
        }
        self.assertEqual(
            masks,
            {
                "callee_saved": [0xFFC0],
                "caller_saved": [0x003F],
                "neither": [0xFFFF0000],
            },
        )

    def test_stage2_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            outputs = []
            for n in range(2):
                out = os.path.join(tmp, f"out{n}")
                proc = _run(
                    [
                        os.path.join(TOOLS, "stage2.py"),
                        "--snapshot",
                        _Snapshot.path,
                        "--src",
                        ROOT,
                        "--out-dir",
                        out,
                    ],
                    env={"PYTHONHASHSEED": str(n)},
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                outputs.append(_tree(out))
            self.assertEqual(outputs[0], outputs[1])
            self.assertNotIn("__pycache__", outputs[0])

    def test_generate_is_deterministic_and_check_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = os.path.join(tmp, "a", "_data")
            second = os.path.join(tmp, "b", "_data")
            generate.generate(first, ROOT)
            generate.generate(second, ROOT)
            self.assertEqual(_tree(first), _tree(second))
            self.assertEqual(generate.compare(first, second), [])
        # The same check `generate.py --check` runs.
        with mock.patch("builtins.print"):
            self.assertEqual(generate.check(ROOT), 0)

    def test_stale_deviation_fails(self):
        deviation = SPECS[0].deviations[0]
        version = self.snapshot["versions"]["ghidra"]
        observed = dict(deviation.observed)
        observed[version] = ("rbx",)
        spec = self._spec(
            deviations=(dataclasses.replace(deviation, observed=observed),)
        )
        with self.assertRaisesRegex(
            GeneratorError, "stale deviation KD-GH-X86-64-FP-CONTROL"
        ):
            self._build([spec])

    def test_unexplained_difference_fails(self):
        deviation = SPECS[0].deviations[0]
        version = self.snapshot["versions"]["ghidra"]
        observed = {k: v for k, v in deviation.observed.items() if k != version}
        spec = self._spec(
            deviations=(dataclasses.replace(deviation, observed=observed),)
        )
        with self.assertRaisesRegex(GeneratorError, "unexplained difference"):
            self._build([spec])

    def test_two_deviations_on_one_field_fail(self):
        deviation = SPECS[0].deviations[0]
        twin = dataclasses.replace(deviation, id="KD-TWIN")
        spec = self._spec(deviations=(deviation, twin))
        with self.assertRaisesRegex(GeneratorError, "exactly one may apply"):
            self._build([spec])

    def test_hand_value_on_a_generated_field_fails(self):
        hand = dict(SPECS[0].hand)
        hand["int_args.registers"] = hand["int_args.alloc"]
        with self.assertRaisesRegex(GeneratorError, "override it with a Deviation"):
            self._build([self._spec(hand=hand)])

    def test_missing_hand_value_fails(self):
        hand = {k: v for k, v in SPECS[0].hand.items() if k != "stack.red_zone"}
        with self.assertRaisesRegex(GeneratorError, "no value for stack.red_zone"):
            self._build([self._spec(hand=hand)])

    def test_uncited_hand_value_fails(self):
        hand = dict(SPECS[0].hand)
        hand["stack.red_zone"] = dataclasses.replace(hand["stack.red_zone"], cite=())
        with self.assertRaisesRegex(GeneratorError, "every overlay entry cites"):
            self._build([self._spec(hand=hand)])

    def test_oracle_disagreements_need_an_ack(self):
        with self.assertRaisesRegex(
            GeneratorError, "unacknowledged oracle disagreement"
        ):
            self._build([self._spec(oracle_acks=())])
        stale = dataclasses.replace(
            SPECS[0].oracle_acks[0],
            id="ACK-STALE",
            field_pattern=SYSV_ID + ":stack.alignment",
        )
        spec = self._spec(oracle_acks=SPECS[0].oracle_acks + (stale,))
        with self.assertRaisesRegex(GeneratorError, "stale oracle ack ACK-STALE"):
            self._build([spec])

    def test_record_confidence_is_its_lowest_entry(self):
        # Master-seed markers remain, so the record is capped at medium.
        self.assertIs(self.record.confidence, abi.Confidence.MEDIUM)
        cells = {k.split("|", 1)[1]: c for k, c in self.result.cells.items()}
        self.assertEqual(cells["confidence"].rules, ("R-CONFIDENCE-MIN",))
        # With every entry at high confidence the curated claim stands ...
        high = {
            path: dataclasses.replace(
                hand,
                confidence="high",
                cite=tuple(c for c in hand.cite if not c.is_master_seed)
                or (PSABI_CITE,),
            )
            for path, hand in SPECS[0].hand.items()
        }
        record = self._build([self._spec(hand=high)], ceiling=0).records[0]
        self.assertIs(record.confidence, abi.Confidence.HIGH)
        # ... and one low entry lowers the whole record.
        low = dict(high)
        low["stack.red_zone"] = dataclasses.replace(
            low["stack.red_zone"], confidence="low"
        )
        record = self._build([self._spec(hand=low)], ceiling=0).records[0]
        self.assertIs(record.confidence, abi.Confidence.LOW)

    def test_master_seed_ceiling(self):
        with self.assertRaisesRegex(GeneratorError, "MASTER_SEED_CEILING"):
            self._build(SPECS, ceiling=0)

    def test_provenance_explains_every_generated_field(self):
        cells = {k.split("|", 1)[1]: c for k, c in self.result.cells.items()}
        for path, dependency in stage2.authority.GENERATED.items():
            self.assertTrue(cells[path].tag.startswith(f"gen:{dependency}:"), path)
        self.assertEqual(
            cells["preservation.callee_saved"].deviations, ("KD-GH-X86-64-FP-CONTROL",)
        )
        self.assertIn("R-CANONICALIZE", cells["fp_args.registers"].rules)

    def test_version_allow_list(self):
        with self.assertRaisesRegex(ValueError, "not a supported dependency set"):
            versions.find("4.0.0", "9.2.194", "9.2.194")
        fake = mock.Mock(__version__="3.3.2")
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            stage1.check_versions(fake, mock.Mock(__version__="9.2.194"), fake)

    @unittest.skipUnless(abi.tables_available(), "no installed ABI tables")
    def test_installed_tables_are_the_generated_ones(self):
        installed = abi.by_id(SYSV_ID)
        self.assertEqual(emit.fingerprint(installed), emit.fingerprint(self.record))
        self.assertIs(abi.resolve(fixtures.X86_64), installed)


class ABIGeneratorNoDataTests(unittest.TestCase):
    """Builds that ship no tables: 3.9, 3.11 and the opt-out."""

    def _generate(self, out, **kwargs):
        with mock.patch.dict(os.environ, {generate.OPT_OUT_ENV: ""}):
            return generate.generate(out, ROOT, **kwargs)

    def _load(self, directory):
        name = "_sw_abi_marker_" + re.sub(r"\W", "_", directory)
        module = stub_loader.mount_data_package("smallworld", directory, name)
        self.addCleanup(sys.modules.pop, module.__name__, None)
        return module

    def test_marker_on_python_without_a_dependency_set(self):
        for version in ((3, 9, 6), (3, 11, 9)):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as tmp:
                out = os.path.join(tmp, "_data")
                files = self._generate(out, version_info=version)
                self.assertEqual(files, ["__init__.py", generate.DIGEST_FILE])
                module = self._load(out)
                self.assertIs(module.AVAILABLE, False)
                self.assertEqual(module.RECORDS, ())
                self.assertEqual(module.FEATURES, ())
                self.assertIn(f"Python {version[0]}.{version[1]}", module.REASON)
                with (
                    mock.patch.object(
                        registry, "_tables", registry._load(module.__name__)
                    ),
                    mock.patch.object(registry, "_override", None),
                ):
                    self.assertFalse(abi.tables_available())
                    self.assertEqual(abi.table_features(), frozenset())
                    with self.assertRaisesRegex(
                        abi.ABITablesUnavailable, "built on Python"
                    ):
                        abi.maybe_resolve(fixtures.X86_64)

    def test_data_pythons(self):
        self.assertIsNone(versions.no_data_reason((3, 10, 0)))
        self.assertIsNone(versions.no_data_reason((3, 12, 0)))
        self.assertIsNone(versions.no_data_reason((3, 14, 0)))
        self.assertIsNotNone(versions.no_data_reason((3, 9, 6)))
        self.assertIsNotNone(versions.no_data_reason((3, 11, 0)))
        self.assertEqual(versions.pinned_set((3, 10)).pypcode, "3.3.3")
        self.assertEqual(versions.pinned_set((3, 13)).pypcode, "4.0.0")

    def test_opt_out(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.dict(os.environ, {generate.OPT_OUT_ENV: "1"}),
        ):
            out = os.path.join(tmp, "_data")
            generate.generate(out, ROOT, version_info=(3, 12, 0))
            self.assertIn(generate.OPT_OUT_ENV, self._load(out).REASON)

    def test_editable_build_keeps_real_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "_data")
            os.makedirs(out)
            real = "AVAILABLE = True\nRECORDS = ()\n"
            with open(os.path.join(out, "__init__.py"), "w") as fh:
                fh.write('"""x"""\n' + real)
            before = _tree(out)
            with mock.patch("sys.stderr", io.StringIO()):  # the stale warning
                self._generate(out, editable=True, version_info=(3, 11, 0))
            # kept (these fake tables have no digests, so they are marked stale)
            after = _tree(out)["__init__.py"]
            self.assertTrue(after.startswith(before["__init__.py"]), after)
            self.assertIn(b"\nSTALE = ", after)
            # a wheel build (not editable) writes what it built
            self._generate(out, editable=False, version_info=(3, 11, 0))
            self.assertIn("AVAILABLE = False", _tree(out)["__init__.py"].decode())

    def test_editable_build_warns_about_stale_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "_data")
            os.makedirs(out)
            with open(os.path.join(out, "__init__.py"), "w") as fh:
                fh.write('"""x"""\nAVAILABLE = True\nRECORDS = ()\n')
            with open(os.path.join(out, generate.DIGEST_FILE), "w") as fh:
                fh.write("full 0\nsources 0\n")
            stderr = io.StringIO()
            with mock.patch("sys.stderr", stderr):
                self._generate(out, editable=True, version_info=(3, 11, 0))
            self.assertIn("keeping STALE ABI tables", stderr.getvalue())
            # ... and the kept tables carry the note the registry warns with
            self.assertIn("inputs", self._load(out).STALE)
            with open(os.path.join(out, generate.DIGEST_FILE), "w") as fh:
                fh.write(f"full 0\nsources {generate.sources_digest(ROOT)}\n")
            stderr = io.StringIO()
            with mock.patch("sys.stderr", stderr):
                self._generate(out, editable=True, version_info=(3, 11, 0))
            self.assertEqual(stderr.getvalue(), "")
            self.assertTrue(generate.has_tables(out))
            with open(os.path.join(out, "__init__.py")) as fh:
                self.assertNotIn("STALE = ", fh.read())

    def test_registry_warns_once_about_stale_tables(self):
        import warnings

        with tempfile.TemporaryDirectory() as tmp:
            text = emit.module("Stale test records.", [("X", fixtures.X86_64_SYSV)])
            text += "AVAILABLE = True\nRECORDS = (X,)\nSTALE = 'the overlay changed'\n"
            with open(os.path.join(tmp, "__init__.py"), "w") as fh:
                fh.write(text)
            module = stub_loader.mount_data_package("smallworld", tmp, "_sw_abi_stale")
            self.addCleanup(sys.modules.pop, module.__name__, None)
            # The registry loads its tables once, at import; loading stale
            # ones warns then, and lookups do not warn again.
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                tables = registry._load(module.__name__)
                with (
                    mock.patch.object(registry, "_tables", tables),
                    mock.patch.object(registry, "_override", None),
                ):
                    abi.resolve(fixtures.X86_64)
                    abi.resolve(fixtures.X86_64)
            stale = [w for w in caught if issubclass(w.category, abi.ABITablesStale)]
            self.assertEqual(len(stale), 1)
            self.assertIn("the overlay changed", str(stale[0].message))
            self.assertEqual(stale[0].filename, __file__)

    def test_stale_warning_points_at_the_users_import(self):
        # Loading happens inside `import smallworld.platforms.abi`; the
        # warning must still be shown, at the importing line.
        with tempfile.TemporaryDirectory() as tmp:
            package = os.path.join(tmp, "pkg")
            shutil.copytree(
                os.path.dirname(os.path.abspath(smallworld.__file__)),
                os.path.join(package, "smallworld"),
                ignore=shutil.ignore_patterns("__pycache__", "_data"),
            )
            data = os.path.join(package, "smallworld", "platforms", "abi", "_data")
            os.makedirs(data)
            text = emit.module("Stale test records.", [("X", fixtures.X86_64_SYSV)])
            text += "AVAILABLE = True\nRECORDS = (X,)\nSTALE = 'the overlay changed'\n"
            with open(os.path.join(data, "__init__.py"), "w") as fh:
                fh.write(text)
            script = os.path.join(tmp, "user.py")
            with open(script, "w") as fh:
                fh.write("import smallworld.platforms.abi\n")
            proc = subprocess.run(
                [sys.executable, script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                env=dict(os.environ, PYTHONPATH=package, PYTHONWARNINGS=""),
                cwd=tmp,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn(f"{script}:1: ABITablesStale", proc.stderr)
            self.assertIn("the overlay changed", proc.stderr)

    def test_compare_needs_real_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "_data")
            self._generate(out, version_info=(3, 9, 6))
            with mock.patch("builtins.print") as printed:
                self.assertEqual(generate.main(["--compare", out, out]), 1)
            self.assertIn("no ABI tables to compare", printed.call_args[0][0])

    def test_opt_out_values(self):
        for value, expected in (
            ("1", True),
            ("yes", True),
            ("TRUE", True),
            ("", False),
            ("0", False),
            ("no", False),
            ("false", False),
        ):
            with (
                self.subTest(value=value),
                mock.patch.dict(os.environ, {generate.OPT_OUT_ENV: value}),
            ):
                self.assertIs(generate.opted_out(), expected)
        with mock.patch.dict(os.environ, {generate.OPT_OUT_ENV: "maybe"}):
            with self.assertRaisesRegex(GeneratorError, "is not understood"):
                generate.opted_out()

    def test_bad_stage1_python(self):
        with mock.patch.dict(
            os.environ, {generate.STAGE1_PYTHON_ENV: "/nonexistent/python"}
        ):
            with self.assertRaisesRegex(GeneratorError, "is not an executable file"):
                generate.stage1_python()

    def test_opt_out_never_loads_the_overlay(self):
        # A broken overlay must not stop a build that ships no tables (the
        # nix dev env builds its smallworld-re that way).
        code = (
            "import sys; sys.path.insert(0, sys.argv[1])\n"
            "import generate\n"
            "print(generate.no_data_reason((3, 12, 0)))\n"
            "print(sorted(m for m in sys.modules if m.startswith('overlay')))\n"
        )
        proc = _run(["-c", code, TOOLS], env={generate.OPT_OUT_ENV: "1"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("switched off", proc.stdout)
        self.assertIn("[]", proc.stdout)

    def test_editable_build_writes_marker_when_there_are_no_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "_data")
            self._generate(out, editable=True, version_info=(3, 9, 6))
            self.assertFalse(generate.has_tables(out))
            self.assertTrue(os.path.exists(os.path.join(out, "__init__.py")))


class ABIGeneratorIsolationTests(unittest.TestCase):
    """Stage 2 depends on nothing but the stdlib, capstone and the platform
    sources."""

    def test_blocker_refuses_heavy_imports(self):
        code = (
            "import sys; sys.path.insert(0, sys.argv[1])\n"
            "import stub_loader\n"
            "stub_loader.install_blocker()\n"
            "for name in ('smallworld', 'angr', 'pypcode', 'smallworld.state'):\n"
            "    try:\n"
            "        __import__(name)\n"
            "    except ImportError as e:\n"
            "        assert 'must not import' in str(e), e\n"
            "    else:\n"
            "        raise SystemExit(name + ' imported')\n"
            "print('ok')\n"
        )
        proc = _run(["-c", code, TOOLS])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "ok")

    def test_stub_loader_loads_only_the_allow_list(self):
        code = (
            "import sys; sys.path.insert(0, sys.argv[1])\n"
            "import stub_loader\n"
            "stub_loader.install_blocker()\n"
            "sw = stub_loader.load(sys.argv[2])\n"
            "assert sw.abi.validate is sw.validate\n"
            "assert sys.modules[stub_loader.DATA] is None\n"
            "assert not sw.abi.tables_available()\n"
            "reason = sw.abi.registry._tables\n"
            "assert stub_loader.DATA in reason, reason\n"
            "assert 'smallworld.platforms.abi._data' not in reason.replace(stub_loader.DATA, '')\n"
            "print('\\n'.join(sorted(m for m, v in sys.modules.items() if v)))\n"
        )
        proc = _run(["-c", code, TOOLS, ROOT])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        loaded = proc.stdout.split()
        stub = [m for m in loaded if m.startswith(stub_loader.STUB + ".")]
        self.assertIn(stub_loader.STUB + ".platforms.abi.model", stub)
        self.assertNotIn(stub_loader.STUB + ".platforms.abi._data", stub)
        for module in stub:
            self.assertIn(module.split(".")[1], stub_loader.ALLOWED, module)
        self.assertFalse([m for m in loaded if m.split(".")[0] in stub_loader.BLOCKED])

    def test_stub_loader_refuses_the_real_smallworld(self):
        code = (
            "import sys; sys.path.insert(0, sys.argv[1])\n"
            "import smallworld.platforms\n"
            "import stub_loader\n"
            "try:\n"
            "    stub_loader.load(sys.argv[2])\n"
            "except RuntimeError as e:\n"
            "    print('refused', e)\n"
        )
        proc = _run(["-c", code, TOOLS, ROOT], env={"PYTHONPATH": ROOT})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("refused", proc.stdout)
        self.assertIn("'smallworld'", proc.stdout)

    def test_stub_loader_refuses_modules_imported_before_it(self):
        code = (
            "import sys; sys.path.insert(0, sys.argv[1])\n"
            "import smallworld.platforms\n"
            "import stub_loader\n"
            "try:\n"
            "    stub_loader.load(sys.argv[2])\n"
            "except RuntimeError as e:\n"
            "    print(e)\n"
        )
        proc = _run(["-c", code, TOOLS, ROOT], env={"PYTHONPATH": ROOT})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("already imported before stage 2", proc.stdout)

    def test_verify_rejects_the_no_data_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {generate.OPT_OUT_ENV: ""}):
                generate.generate(tmp + "/_data", ROOT, version_info=(3, 9, 6))
            proc = _run(
                [
                    os.path.join(TOOLS, "stage2.py"),
                    "--verify",
                    tmp + "/_data",
                    "--src",
                    ROOT,
                ]
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("AVAILABLE = False, not True", proc.stderr)

    def test_tables_mounted_before_load_are_served(self):
        with tempfile.TemporaryDirectory() as tmp:
            text = emit.module("Test records.", [("X", fixtures.X86_64_SYSV)])
            text += "AVAILABLE = True\nRECORDS = (X,)\n"
            with open(os.path.join(tmp, "__init__.py"), "w") as fh:
                fh.write(text)
            code = (
                "import sys; sys.path.insert(0, sys.argv[1])\n"
                "import stub_loader\n"
                "stub_loader.install_blocker()\n"
                "stub_loader.mount_data_package(stub_loader.STUB, sys.argv[3], "
                "src_root=sys.argv[2])\n"
                "sw = stub_loader.load(sys.argv[2])\n"
                "print([r.id for r in sw.abi.all_records()])\n"
            )
            proc = _run(["-c", code, TOOLS, ROOT, tmp])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn(SYSV_ID, proc.stdout)

    def test_stale_warning_points_at_import_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            package = os.path.join(tmp, "pkg")
            shutil.copytree(
                os.path.dirname(os.path.abspath(smallworld.__file__)),
                os.path.join(package, "smallworld"),
                ignore=shutil.ignore_patterns("__pycache__", "_data"),
            )
            data = os.path.join(package, "smallworld", "platforms", "abi", "_data")
            os.makedirs(data)
            text = emit.module("Stale test records.", [("X", fixtures.X86_64_SYSV)])
            text += "AVAILABLE = True\nRECORDS = (X,)\nSTALE = 'the overlay changed'\n"
            with open(os.path.join(data, "__init__.py"), "w") as fh:
                fh.write(text)
            script = os.path.join(tmp, "user.py")
            with open(script, "w") as fh:
                fh.write(
                    "import importlib\nimportlib.import_module('smallworld.platforms.abi')\n"
                )
            proc = subprocess.run(
                [sys.executable, script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                env=dict(os.environ, PYTHONPATH=package, PYTHONWARNINGS=""),
                cwd=tmp,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn(f"{script}:2: ABITablesStale", proc.stderr)

    def test_stage1_never_imports_smallworld(self):
        with open(os.path.join(TOOLS, "stage1.py")) as fh:
            source = fh.read()
        self.assertNotRegex(source, r"(?m)^\s*(import|from)\s+smallworld")

    def test_naming_is_reexported(self):
        from smallworld.instructions import pcode_naming
        from smallworld.platforms import naming

        self.assertIs(pcode_naming.canonicalize_register, naming.canonicalize_register)
        self.assertIs(pcode_naming.register_alias, naming.register_alias)
        self.assertIs(pcode_naming._platform_name, naming._platform_name)
        platdef = smallworld.platforms.PlatformDef.for_platform(fixtures.X86_64)
        self.assertEqual(naming.canonicalize_register("xmm3_qa", platdef), "xmm3")


class ABIEmitterTests(unittest.TestCase):
    def _roundtrip(self, records):
        text = emit.module(
            "Test records.", [(f"R{i}", r) for i, r in enumerate(records)]
        )
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "__init__.py"), "w") as fh:
                fh.write(text)
            module = stub_loader.mount_data_package(
                "smallworld", tmp, "_sw_abi_emit_test"
            )
            self.addCleanup(sys.modules.pop, module.__name__, None)
            return text, [getattr(module, f"R{i}") for i in range(len(records))]

    def test_fixture_records_round_trip(self):
        text, loaded = self._roundtrip(fixtures.RECORDS)
        for original, again in zip(fixtures.RECORDS, loaded):
            self.assertEqual(emit.fingerprint(again), emit.fingerprint(original))
        self.assertEqual(text, self._roundtrip(fixtures.RECORDS)[0])

    def test_output_is_black_stable(self):
        try:
            import black
        except ImportError:
            self.skipTest("black is not installed")
        text, _ = self._roundtrip(fixtures.RECORDS)
        self.assertEqual(black.format_str(text, mode=black.Mode()), text)

    def test_enums_never_go_through_str(self):
        emitter = emit.Emitter()
        self.assertEqual(emitter.value(abi.Role.FP_VALUE), "Role.FP_VALUE")
        self.assertEqual(emitter.value(0xFFC0, field="preserved_mask"), "0xFFC0")
        self.assertEqual(emitter.value(("a",)), '("a",)')

    def test_formatters_skip_generated_files(self):
        generated = [
            f"{DATA_REL}/{name}".replace(os.sep, "/")
            for name in ("__init__.py", "x86.py")
        ]
        with open(os.path.join(ROOT, "pyproject.toml")) as fh:
            pyproject = fh.read()
        black = re.search(r"^force-exclude = '(.*)'$", pyproject, re.M)
        self.assertIsNotNone(black)
        for path in generated:
            self.assertRegex("/" + path, black.group(1))
        with open(os.path.join(ROOT, ".isort.cfg")) as fh:
            isort = re.search(r"^extend_skip_glob = (.*)$", fh.read(), re.M)
        self.assertIsNotNone(isort)
        import fnmatch

        for path in generated:
            self.assertTrue(fnmatch.fnmatch(path, isort.group(1).strip()), path)
        with open(os.path.join(ROOT, ".flake8")) as fh:
            self.assertIn("smallworld/platforms/abi/_data", fh.read())
        self.assertIn("smallworld/platforms/abi/_data)/", pyproject)
        with open(os.path.join(ROOT, ".gitignore")) as fh:
            self.assertIn("/smallworld/platforms/abi/_data/", fh.read())
