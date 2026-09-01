"""Unit tests for the pcode-based instruction use/def analysis.

Three layers are covered:

* PcodeNamingTests — the Ghidra-name -> PlatformDef-name adapter on its
  own. Needs no pyghidra, so it runs on a base install too.

* UseDefCorpusTests — regression over the validation corpus in this
  directory (see README.md): every entry must agree with hand-written
  ground truth at least under the harness's normalized comparison, and
  the count matching *strictly* must not fall.

* InstructionUseDefTests — the consumer-facing Instruction.reads /
  .writes API: results must be sets of Operand objects whose register
  names exist in the SmallWorld platform definition (so they can be
  concretized against an emulator), must not be empty, must contain the
  registers the instruction architecturally names, with spot checks of
  exact semantics.

These run on pypcode -- SLEIGH's C++ translator, a core dependency -- so
they need no JVM and no Ghidra install; they skip cleanly if pypcode is
somehow absent. The one class that DOES boot a JVM is
GhidraMachdefRegisterAliasTests, which compares the naming layer against
the Ghidra EMULATOR's machine definitions; those import Ghidra's Java
classes at module scope, so they need pyghidra and skip without it.
"""

import importlib
import importlib.util
import multiprocessing
import os
import subprocess
import sys
import textwrap
import unittest
import unittest.mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

try:
    import pyghidra  # noqa: F401

    HAVE_PYGHIDRA = True
except Exception:
    # Deliberately broader than ImportError. pyghidra is an optional extra
    # whose import touches jpype and the Ghidra install, so a JVM/ABI mismatch
    # or an unreadable GHIDRA_INSTALL_DIR can raise RuntimeError/OSError -- and
    # tests/unit.py imports this module at collection time, so anything that
    # escapes here takes the entire unit suite down instead of skipping the
    # p-code tests.
    HAVE_PYGHIDRA = False

try:
    import pypcode  # noqa: F401

    HAVE_PYPCODE = True
except Exception:
    # pypcode is a core dependency, so this is a broken install rather than a
    # missing extra -- but skipping beats taking tests/unit.py down at
    # collection time, which importing this module would otherwise do.
    HAVE_PYPCODE = False


def _load_corpus_harness():
    # Loaded by explicit path: "harness" as a module name would collide
    # with the tests/harness framework package.
    spec = importlib.util.spec_from_file_location(
        "pcode_use_def_corpus_harness", os.path.join(HERE, "harness.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PcodeNamingTests(unittest.TestCase):
    """The Ghidra-name -> PlatformDef-name adapter, on its own.

    This layer had no coverage at all: the corpus checks the engine in
    *Ghidra's* namespace and never runs `canonicalize_operand`, and the
    Instruction-level tests only see the result after the mapping has already
    happened. A register the mapping drops or misnames simply vanishes, logged
    at debug.

    Needs no pyghidra -- pcode_naming imports none -- so unlike everything
    else in this file it also runs on a base install.
    """

    @staticmethod
    def _platdef(arch, byteorder="LITTLE"):
        from smallworld.platforms import (
            Architecture,
            Byteorder,
            Platform,
            PlatformDef,
        )

        return PlatformDef.for_platform(
            Platform(Architecture[arch], Byteorder[byteorder])
        )

    def _canon(self, arch, byteorder, name):
        """canonicalize_operand of one register, as a name or None."""
        from smallworld.instructions import RegisterOperand
        from smallworld.instructions.pcode_naming import canonicalize_operand

        out = canonicalize_operand(
            RegisterOperand(name), self._platdef(arch, byteorder)
        )
        return None if out is None else out.name

    def test_x86_flag_bits_and_vector_lanes(self):
        self.assertEqual(self._canon("X86_64", "LITTLE", "cf"), "rflags")
        self.assertEqual(self._canon("X86_64", "LITTLE", "zf"), "rflags")
        self.assertEqual(self._canon("X86_32", "LITTLE", "cf"), "eflags")
        self.assertEqual(self._canon("X86_64", "LITTLE", "xmm0_qa"), "xmm0")
        # A name the two namespaces already agree on passes through.
        self.assertEqual(self._canon("X86_64", "LITTLE", "rax"), "rax")

    def test_mips32_accumulators(self):
        self.assertEqual(self._canon("MIPS32", "BIG", "hi"), "hi0")
        self.assertEqual(self._canon("MIPS32", "BIG", "lo"), "lo0")

    def test_aarch64_vector_and_powerpc_fpscr(self):
        # zN is Ghidra's full vector register; qN is the widest lane modelled.
        self.assertEqual(self._canon("AARCH64", "LITTLE", "z3"), "q3")
        self.assertEqual(self._canon("POWERPC32", "BIG", "fp_fx"), "fpscr")

    def test_arm_condition_flags_reach_the_status_register(self):
        """Ghidra's four one-bit ARM flags map to the platform's status
        register -- cpsr on the R/A-series, psr on the M-series -- so `cmp`
        no longer reports writing nothing. The cost is a spurious read on
        plain data-processing instructions; see the note in arm.py."""
        for arch, expected in (
            ("ARM_V7A", "cpsr"),
            ("ARM_V7R", "cpsr"),
            ("ARM_V5T", "psr"),
            ("ARM_V6M", "psr"),
            ("ARM_V7M", "psr"),
        ):
            with self.subTest(arch=arch):
                for flag in ("ng", "zr", "cy", "ov"):
                    self.assertEqual(self._canon(arch, "LITTLE", flag), expected)

    def test_unmodelled_register_is_dropped(self):
        self.assertIsNone(self._canon("X86_64", "LITTLE", "not_a_register"))

    def test_collapse_widened_defs_keeps_the_narrower_name(self):
        from smallworld.instructions import RegisterOperand
        from smallworld.instructions.pcode_naming import collapse_widened_defs

        platdef = self._platdef("X86_64", "LITTLE")
        # Ghidra models a 32-bit x86-64 write as zero-extending, so `mov
        # ecx, eax` defs both; the architectural destination is ecx.
        self.assertEqual(
            collapse_widened_defs(
                {RegisterOperand("ecx"), RegisterOperand("rcx")}, platdef
            ),
            {RegisterOperand("ecx")},
        )
        # Nothing to collapse: left alone.
        self.assertEqual(
            collapse_widened_defs({RegisterOperand("rax")}, platdef),
            {RegisterOperand("rax")},
        )

    # Known gaps, marked expected so they are recorded rather than
    # forgotten. Fixing one turns it into an unexpected success, which fails
    # the suite and forces the marker off. Do not "fix" one by deleting it.

    @unittest.expectedFailure
    def test_full_width_simd_write_is_reported_whole(self):
        """collapse_widened_defs drops the parent whenever a sub-register is
        also defined, which is right for x86 zero-extension but not for AVX:
        ymm0's upper half is written by its own varnodes, so a 256-bit write
        reports only xmm0. Telling the two apart needs the architectural
        destination (Capstone names it; this layer is not given it)."""
        from smallworld.instructions import RegisterOperand
        from smallworld.instructions.pcode_naming import collapse_widened_defs

        platdef = self._platdef("X86_64", "LITTLE")
        defs = {RegisterOperand("xmm0"), RegisterOperand("ymm0")}
        self.assertIn(RegisterOperand("ymm0"), collapse_widened_defs(defs, platdef))

    def test_aarch64_condition_flags_reach_a_register(self):
        """ng/zr/cy/ov alias to nzcv -- the PSTATE condition-flag field that
        mrs/msr address as a system register. Unmodelled, `cmp x0, x1`
        reported writing nothing at all."""
        for flag in ("ng", "zr", "cy", "ov", "nzcv"):
            self.assertEqual(self._canon("AARCH64", "LITTLE", flag), "nzcv")

    def test_powerpc_xer_bits_reach_a_register(self):
        """XER is SPR 1 and the platform models it as spr_xer; there is no
        plain "xer" RegisterDef, so aliasing to that dropped every carry and
        overflow edge (20 of 79 corpus_ppc32.json entries name xer_*)."""
        self.assertEqual(self._canon("POWERPC32", "BIG", "xer_so"), "spr_xer")
        self.assertEqual(self._canon("POWERPC32", "BIG", "xer_ca"), "spr_xer")

    def test_mips64_32bit_register_views_reduce_to_the_register(self):
        """Ghidra names the 32-bit view of a MIPS64 GPR <reg>_lo and the upper
        half <reg>_hi; both are the architectural register for use/def, the
        same reduction eax -> rax gets. Unmapped, every 32-bit MIPS64 op
        (addu, sll, lw) reported empty operands."""
        self.assertEqual(self._canon("MIPS64", "BIG", "a0_lo"), "a0")
        self.assertEqual(self._canon("MIPS64", "BIG", "a0_hi"), "a0")
        # ...and the accumulators, which SmallWorld numbers (there are four).
        self.assertEqual(self._canon("MIPS64", "BIG", "hi"), "hi0")
        self.assertEqual(self._canon("MIPS64", "BIG", "lo"), "lo0")

    def test_mips64_o32_names_are_translated_to_n64(self):
        """Ghidra names MIPS64 GPRs O32-style, SmallWorld N64-style, and the
        two disagree about what a name MEANS rather than how it is spelled:
        Ghidra's t0 is $8, which N64 calls a4, while N64's t0 is $12, which
        Ghidra calls t4. Passing the name through unchanged landed on a
        different physical register and nothing detected it."""
        # $8-$11: Ghidra t0-t3 -> N64 a4-a7
        self.assertEqual(self._canon("MIPS64", "BIG", "t0"), "a4")
        self.assertEqual(self._canon("MIPS64", "BIG", "t3"), "a7")
        # $12-$15: Ghidra t4-t7 -> N64 t0-t3
        self.assertEqual(self._canon("MIPS64", "BIG", "t4"), "t0")
        self.assertEqual(self._canon("MIPS64", "BIG", "t7"), "t3")
        # Applied after the _lo reduction, so the sub-register view of an
        # O32-named register lands on the right N64 register too.
        self.assertEqual(self._canon("MIPS64", "BIG", "t0_lo"), "a4")
        # $24-$25 agree in both ABIs and must NOT be renamed.
        self.assertEqual(self._canon("MIPS64", "BIG", "t8"), "t8")
        self.assertEqual(self._canon("MIPS64", "BIG", "t9"), "t9")

    def test_memory_operand_base_and_index_are_mapped_and_validated(self):
        """A memory operand's base/index are register names too. Passed
        through raw, a Ghidra-only name survived into an operand whose
        .address() raises the moment a consumer resolves it."""
        from smallworld.instructions.bsid import BSIDMemoryReferenceOperand
        from smallworld.instructions.pcode_naming import canonicalize_operand

        amd64 = self._platdef("X86_64", "LITTLE")
        # x86-64 segment addressing reads Ghidra's FS_OFFSET, which AMD64
        # aliases to the fsbase register it models. The reference must survive
        # -- dropping it reported the stack-protector read at the top of most
        # functions as reading nothing -- and it must survive in the shape
        # Capstone produces for the same instruction, segment="fs" with no
        # base, or consumers that classify on `segment` stop recognizing it.
        segment = BSIDMemoryReferenceOperand(base="fs_offset", offset=0x28, size=8)
        mapped = canonicalize_operand(segment, amd64)
        self.assertIsNotNone(mapped)
        self.assertEqual(
            (mapped.segment, mapped.base, mapped.offset, mapped.size),
            ("fs", None, 0x28, 8),
        )

        # gs too, and an already-canonical fsbase base (not just Ghidra's
        # spelling) folds the same way.
        gs = BSIDMemoryReferenceOperand(base="gsbase", offset=0x13, size=8)
        mapped_gs = canonicalize_operand(gs, amd64)
        self.assertIsNotNone(mapped_gs)
        self.assertEqual((mapped_gs.segment, mapped_gs.base), ("gs", None))

        # An operand that already names its segment is left as it is.
        already = BSIDMemoryReferenceOperand(segment="fs", offset=0x28, size=8)
        self.assertEqual(canonicalize_operand(already, amd64).segment, "fs")

        # i386 models the fs/gs selectors but no segment base register, so it
        # has no fold to apply and the unresolvable base is still dropped.
        i386 = self._platdef("X86_32", "LITTLE")
        self.assertEqual(i386.segment_base_registers, {})
        self.assertIsNone(
            canonicalize_operand(
                BSIDMemoryReferenceOperand(base="fs_offset", offset=0x28, size=4), i386
            )
        )

        # A base the platform genuinely does not model still goes, since
        # without a base there is no address to compute.
        unresolvable = BSIDMemoryReferenceOperand(
            base="not_a_register", offset=0, size=8
        )
        self.assertIsNone(canonicalize_operand(unresolvable, amd64))

        # A resolvable one is preserved exactly.
        ok = BSIDMemoryReferenceOperand(base="rdx", index="rcx", scale=4, offset=16)
        out = canonicalize_operand(ok, amd64)
        self.assertIsNotNone(out)
        self.assertEqual(
            (out.base, out.index, out.scale, out.offset), ("rdx", "rcx", 4, 16)
        )

        # And a mappable-but-differently-named one is rewritten, not dropped.
        mips64 = self._platdef("MIPS64", "BIG")
        renamed = canonicalize_operand(
            BSIDMemoryReferenceOperand(base="t0", offset=8, size=8), mips64
        )
        self.assertIsNotNone(renamed)
        self.assertEqual(renamed.base, "a4")
        self.assertEqual((renamed.offset, renamed.size), (8, 8))


@unittest.skipUnless(HAVE_PYGHIDRA, "pyghidra is not installed")
class GhidraMachdefRegisterAliasTests(unittest.TestCase):
    """PlatformDef.ghidra_register_aliases must agree with the Ghidra machine
    def it mirrors.

    The machine def maps SmallWorld name -> Ghidra name and needs a JVM to
    import; the platform definition carries the inverse so the p-code naming
    layer can read it without one. Two statements of one fact, so assert they
    stay agreed rather than letting them drift.
    """

    @staticmethod
    def _canonical(name, platdef):
        """Follow RegisterAliasDef.parent to the underlying physical
        register, so two names for one register compare equal."""
        from smallworld.platforms import RegisterAliasDef

        seen = set()
        while name not in seen:
            seen.add(name)
            reg = platdef.registers.get(name)
            if not isinstance(reg, RegisterAliasDef):
                return name
            name = reg.parent
        return name

    def _check(self, machdef_cls, platdef_cls):
        """Every Ghidra register name the machine def knows must resolve,
        through the naming layer, to the same PHYSICAL register the machine
        def says it is."""
        from smallworld.instructions.pcode_naming import _platform_name

        platdef = platdef_cls()
        for smallworld_name, ghidra_name in machdef_cls._registers.items():
            if ghidra_name is None or smallworld_name.isdigit():
                continue  # unmapped, or a numeric alias the analysis never sees
            with self.subTest(ghidra=ghidra_name, smallworld=smallworld_name):
                resolved = _platform_name(ghidra_name, platdef)
                self.assertIsNotNone(
                    resolved,
                    msg=f"Ghidra {ghidra_name!r} is SmallWorld "
                    f"{smallworld_name!r} per the machine def, but the naming "
                    f"layer drops it",
                )
                self.assertEqual(
                    self._canonical(resolved, platdef),
                    self._canonical(smallworld_name, platdef),
                    msg=f"Ghidra {ghidra_name!r} is SmallWorld "
                    f"{smallworld_name!r} per the machine def, but the naming "
                    f"layer resolves it to {resolved!r} -- a different "
                    f"physical register",
                )

    @staticmethod
    def _start_jvm():
        """Boot the JVM for the tests that need Ghidra's Java machdefs.

        The use/def analysis no longer starts one -- it runs on pypcode, which
        wraps SLEIGH's C++ directly -- so these tests, which compare that
        analysis against the Ghidra EMULATOR's machine definitions, have to
        boot the JVM themselves. The SymZ3 extension is prepared first because
        Ghidra discovers extensions only while its Application initializes,
        during the first pyghidra.start() in the process; without that, a
        GhidraSymbolicEmulator constructed later in the same process cannot
        resolve its classes.
        """
        from smallworld.emulators.ghidra import symz3_loader

        try:
            symz3_loader.prepare_extension()
        except Exception:
            pass  # optional; a later GhidraSymbolicEmulator reports it itself

        # pyghidra is bound at module scope; this class is skipped without it.
        pyghidra.start()

    def test_mips64_names_resolve_to_the_right_physical_register(self):
        self._start_jvm()  # machdefs import Ghidra's Java classes at module scope

        from smallworld.emulators.ghidra.machdefs.mips64 import (
            MIPS64BEMachineDef,
        )
        from smallworld.platforms.defs.mips64 import MIPS64BE

        self._check(MIPS64BEMachineDef, MIPS64BE)

    def test_mips32_names_resolve_to_the_right_physical_register(self):
        self._start_jvm()

        from smallworld.emulators.ghidra.machdefs.mips import MIPSBEMachineDef
        from smallworld.platforms.defs.mips import MIPS32BE

        self._check(MIPSBEMachineDef, MIPS32BE)


@unittest.skipUnless(HAVE_PYPCODE, "pypcode is not installed")
class PcodeAnalysisRobustnessTests(unittest.TestCase):
    """Failure modes of analyze() and its caching."""

    # Instructions whose p-code uses mnemonics the op table once misspelled
    # (Ghidra emits bare CEIL/FLOOR/ROUND, not FLOAT_*), each of which raised
    # a bare KeyError out of analyze(). cvtsd2si is an ordinary C
    # double-to-int cast, so this was reachable from unremarkable code.
    MNEMONIC_REGRESSIONS = [
        ("x86:LE:64:default", "f20f2dc0", "cvtsd2si eax, xmm0"),
        ("x86:LE:64:default", "d9fc", "frndint"),
        ("MIPS:BE:32:default", "4600000e", "ceil.w.s"),
        ("MIPS:BE:32:default", "4600000f", "floor.w.s"),
    ]

    def test_float_conversion_mnemonics_analyze(self):
        from smallworld.instructions.pcode_use_def import analyze

        for lang, hexbytes, desc in self.MNEMONIC_REGRESSIONS:
            with self.subTest(instruction=desc):
                result = analyze(bytes.fromhex(hexbytes), lang, 0)
                self.assertIsNotNone(result, f"{desc} did not decode")

    def test_op_table_covers_every_sleigh_opcode(self):
        """The op table is an allowlist keyed by SLEIGH's OpCode names, so it
        silently rots against a new pypcode. Compare it to the real table.

        Enumerating pypcode rather than Ghidra's Java PcodeOp is the point:
        the analysis reads SLEIGH's names now, and the two vocabularies do
        not agree -- Ghidra spells the rounding ops CEIL/FLOOR/ROUND where
        SLEIGH spells them FLOAT_CEIL/FLOAT_FLOOR/FLOAT_ROUND. Checking
        against the wrong one would pass while every float conversion took
        the generic path.
        """
        # pypcode is bound at module scope; this class is skipped without it.
        from smallworld.instructions.pcode_use_def import _PCODE_OP

        sleigh_names = {op.name for op in pypcode.OpCode}
        self.assertTrue(sleigh_names, "could not read SLEIGH's opcode table")
        # IMARK marks instruction boundaries in a translation and is filtered
        # out before the use/def walk ever sees an op, so it is deliberately
        # absent from the table.
        missing = sorted(sleigh_names - {m.name for m in _PCODE_OP} - {"IMARK"})
        self.assertEqual(
            missing,
            [],
            msg=f"_PCODE_OP is missing opcodes SLEIGH emits: {missing}. "
            f"They no longer raise KeyError (see _mnemonic_of), but each one "
            f"takes the generic path, so any special handling is skipped.",
        )

    def test_unimplemented_semantics_raise_rather_than_report_empty(self):
        """Ghidra's UNIMPLEMENTED means 'no semantics for this instruction'.
        Its inputs and outputs are empty, so reporting the generic result
        would be indistinguishable from a genuine nop."""
        from smallworld.instructions.pcode_use_def import UseDefError, analyze

        with self.assertRaises(UseDefError):
            analyze(bytes.fromhex("4afc"), "68000:BE:32:default", 0)  # m68k illegal

    def test_bare_callother_raises_rather_than_reporting_a_nop(self):
        """Ghidra models trap instructions as a lone CALLOTHER -- an opaque
        user-op -- so their computed use/def is empty, indistinguishable
        from a nop. Saying we don't know beats asserting nothing happens;
        the consumer degrades to an empty set WITH a warning."""
        from smallworld.instructions.pcode_use_def import UseDefError, analyze

        for lang, hexbytes, desc in (
            ("x86:LE:32:default", "cd80", "int 0x80"),
            ("AARCH64:LE:64:v8A", "010000d4", "svc #0"),
            ("PowerPC:BE:32:default", "44000002", "sc"),
            ("MIPS:BE:32:default", "0000000c", "syscall"),
        ):
            with self.subTest(instruction=desc):
                with self.assertRaises(UseDefError):
                    analyze(bytes.fromhex(hexbytes), lang, 0)

    def test_callother_beside_real_pcode_still_reports(self):
        """The raise is only for instructions whose ENTIRE effect is opaque.
        Where CALLOTHER sits beside real p-code, the computed sets are
        partial-but-true and must be reported: rdtsc defs eax/edx, x86-64
        syscall defs its r11/rcx side effects, and a lock-prefixed RMW has
        full semantics around the lock. pause has no CALLOTHER at all, and
        its empty sets are the genuine answer."""
        from smallworld.instructions import RegisterOperand
        from smallworld.instructions.pcode_use_def import UseDefError, analyze

        rdtsc = analyze(bytes.fromhex("0f31"), "x86:LE:64:default", 0)
        self.assertIn(RegisterOperand("eax"), rdtsc.defs)
        # x86-64 syscall used to belong in this list: Ghidra's x86 spec 4.7
        # models its r11/rcx side effects beside the CALLOTHER, so the sets
        # were partial-but-true. The spec pypcode bundles (4.6) models the
        # instruction as a bare CALLOTHER with no side effects at all, which
        # lands it in the opaque case below instead. Nothing about the
        # analysis changed -- only which SLEIGH spec describes the
        # instruction -- so assert what this spec actually says.
        with self.assertRaises(UseDefError):
            analyze(bytes.fromhex("0f05"), "x86:LE:64:default", 0)
        xadd = analyze(bytes.fromhex("f0480fc10f"), "x86:LE:64:default", 0)
        self.assertTrue(xadd.uses and xadd.defs)
        pause = analyze(bytes.fromhex("f390"), "x86:LE:64:default", 0)
        self.assertEqual((pause.uses, pause.defs), ((), ()))

    def test_failed_decode_is_not_memoized(self):
        """_pcode_use_def turns None into an empty use/def set, so a cached
        None would report an instruction as a no-op for the whole process."""
        from smallworld.instructions.pcode_use_def import analyze

        analyze.cache_clear()
        undecodable = b"\xff\xff\xff\xff"
        self.assertIsNone(analyze(undecodable, "MIPS:BE:32:default", 0))
        self.assertIsNone(analyze(undecodable, "MIPS:BE:32:default", 0))
        self.assertEqual(analyze.cache_info().currsize, 0, "a failed decode was cached")

    def test_warm_is_idempotent_and_populates_the_cache(self):
        """warm() moves the one-time SLEIGH context build off the first
        analysis, for callers where that latency lands somewhere it matters
        (an emulator's per-instruction callback)."""
        from smallworld.instructions import pcode_use_def

        pcode_use_def.warm("x86:LE:64:default")
        self.assertIn("x86:LE:64:default", pcode_use_def._contexts)
        first = pcode_use_def._contexts["x86:LE:64:default"]
        pcode_use_def.warm("x86:LE:64:default")  # second call: no-op
        self.assertIs(first, pcode_use_def._contexts["x86:LE:64:default"])

    def test_successful_result_is_still_memoized(self):
        from smallworld.instructions.pcode_use_def import analyze

        analyze.cache_clear()
        for _ in range(2):
            analyze(bytes.fromhex("4801d8"), "x86:LE:64:default", 0)
        info = analyze.cache_info()
        self.assertEqual((info.hits, info.currsize), (1, 1))


class PcodeUseDefDegradationTests(unittest.TestCase):
    """reads/writes are properties, called from the colorizer's callbacks and
    from Unicorn's fault handler -- which is itself already handling an
    emulation failure. The Capstone backend never raised at them; neither may
    the pcode one.

    Needs no pyghidra: analyze is replaced, and since the analysis moved to
    pypcode nothing in pcode_use_def imports pyghidra at all. tests/unit.py
    imports this module into the main suite, so an import that could fail
    would ERROR the whole suite rather than skip.
    """

    def test_use_def_error_degrades_to_an_empty_set(self):
        import smallworld.instructions.instructions as instructions_mod
        from smallworld.instructions import Instruction
        from smallworld.platforms import Architecture, Byteorder, Platform

        pcode_use_def = importlib.import_module("smallworld.instructions.pcode_use_def")
        platform = Platform(Architecture.X86_64, Byteorder.LITTLE)
        insn = Instruction.from_bytes(
            bytes.fromhex("4801d8"), 0x1000, platform, use_def_backend="pcode"
        )

        def _raise(*args, **kwargs):
            raise pcode_use_def.UseDefError("synthetic")

        real = pcode_use_def.analyze
        pcode_use_def.analyze = _raise
        try:
            # UseDefError is the ROUTINE limitation case, logged at info;
            # warnings are reserved for configuration problems and bugs.
            with self.assertLogs(instructions_mod.logger, level="INFO") as logs:
                self.assertEqual(insn.reads, set())
                self.assertEqual(insn.writes, set())
        finally:
            pcode_use_def.analyze = real
        self.assertTrue(any("synthetic" in line for line in logs.output))
        self.assertFalse(any(line.startswith("WARNING") for line in logs.output))

    def test_unexpected_analysis_failure_propagates(self):
        """Anything that is not UseDefError/ValueError is a bug here or new
        Ghidra behavior, and propagates (tleek's call): reclassifying it as
        "the instruction could not be analyzed" would be false, and a bug
        that only warns is a bug that hides."""
        from smallworld.instructions import Instruction
        from smallworld.platforms import Architecture, Byteorder, Platform

        pcode_use_def = importlib.import_module("smallworld.instructions.pcode_use_def")
        platform = Platform(Architecture.X86_64, Byteorder.LITTLE)
        insn = Instruction.from_bytes(
            bytes.fromhex("89cb"), 0x1000, platform, use_def_backend="pcode"
        )

        def _raise(*args, **kwargs):
            raise KeyError("synthetic-bug")

        real = pcode_use_def.analyze
        pcode_use_def.analyze = _raise
        try:
            with self.assertRaises(KeyError):
                insn.reads
        finally:
            pcode_use_def.analyze = real

    def test_capstone_writes_does_not_resolve_a_platform_def(self):
        """PlatformDef.for_platform walks every subclass uncached, costing
        10-100x the rest of _capstone_use_def. The writes path reads nothing
        from the platdef, and this is the DEFAULT backend on a property the
        colorizer and Unicorn hit once per instruction -- so it must not pay
        for the lookup, nor start raising for a platform that has no
        PlatformDef at all. Asserted behaviourally; a timing test would flake.
        """
        from smallworld.instructions import Instruction
        from smallworld.platforms import (
            Architecture,
            Byteorder,
            Platform,
            PlatformDef,
        )

        platform = Platform(Architecture.MIPS32, Byteorder.BIG)
        insn = Instruction.from_bytes(
            bytes.fromhex("8fa80004"), 0x1000, platform, use_def_backend="capstone"
        )  # lw t0, 4(sp); pinned to Capstone -- this tests that path

        def _explode(cls, *args, **kwargs):
            raise AssertionError("writes resolved a PlatformDef it never reads")

        # patch.object, not a manual save/restore: `PlatformDef.for_platform`
        # reads as an already-BOUND method, so assigning it back would replace
        # the classmethod descriptor with an object permanently bound to
        # PlatformDef -- a leak into every test that runs after this one, now
        # that tests/unit.py imports this module.
        with unittest.mock.patch.object(
            PlatformDef, "for_platform", classmethod(_explode)
        ):
            self.assertTrue(insn.writes)
            # reads too, since fetches() took over the implicit-dereference
            # handling that used to make the use path consult the platdef.
            self.assertTrue(insn.reads)


class GetCmpInfoDegradationTests(unittest.TestCase):
    """get_cmp_info runs per instruction inside a live trace, so an
    uninterpretable compare must degrade to no-cmp-info, not abort the
    run. Needs no pyghidra and no emulator: the degrade happens first."""

    def test_compare_on_an_isa_with_no_instruction_subclass_degrades(self):
        """SuperH (and riscv, tricore, m68k, ...) define compare_mnemonics
        but have no Instruction subclass, so from_capstone raises
        ValueError -- which used to escape because it sat outside the
        function's try."""
        import capstone as cs

        from smallworld.analyses.trace_execution import get_cmp_info
        from smallworld.platforms import Architecture, Byteorder, Platform

        platform = Platform(Architecture.SUPERH_SH2A_FPU, Byteorder.BIG)
        md = cs.Cs(cs.CS_ARCH_SH, cs.CS_MODE_SH2A | cs.CS_MODE_BIG_ENDIAN)
        md.detail = True
        insn = next(md.disasm(bytes.fromhex("3450"), 0x1000))  # cmp/eq r5,r4
        self.assertEqual(insn.mnemonic, "cmp/eq")
        self.assertEqual(get_cmp_info(platform, None, insn), [])


class MemoryOperandIdentityTests(unittest.TestCase):
    """Two accesses to one address at different widths are different
    accesses. Needs no pyghidra."""

    def test_size_participates_in_equality(self):
        from smallworld.instructions.bsid import BSIDMemoryReferenceOperand

        one = BSIDMemoryReferenceOperand(base="rsp", offset=-8, size=1)
        eight = BSIDMemoryReferenceOperand(base="rsp", offset=-8, size=8)
        # They still render identically -- the colorizer truth files and the
        # trace harness's expected output depend on that spelling.
        self.assertEqual(repr(one), repr(eight))
        self.assertNotEqual(one, eight)
        self.assertEqual(len({one, eight}), 2)

    def test_same_size_still_compares_equal(self):
        from smallworld.instructions.bsid import BSIDMemoryReferenceOperand

        a = BSIDMemoryReferenceOperand(base="rsp", offset=-8, size=8)
        b = BSIDMemoryReferenceOperand(base="rsp", offset=-8, size=8)
        self.assertEqual(a, b)
        self.assertEqual(len({a, b}), 1)

    def test_comparison_against_a_register_operand_is_false(self):
        from smallworld.instructions import RegisterOperand
        from smallworld.instructions.bsid import BSIDMemoryReferenceOperand

        self.assertNotEqual(
            BSIDMemoryReferenceOperand(base="rsp", size=8), RegisterOperand("rsp")
        )

    def test_non_x86_memory_reference_operand_resolves(self):
        """get_cmp_info calls _memory_reference_operand, which used to exist
        only on x86Instruction -- so a memory-operand compare on any other
        platform raised AttributeError. Latent only while RISC compares stay
        register-only."""
        import capstone as cs

        from smallworld.instructions import Instruction

        md = cs.Cs(cs.CS_ARCH_PPC, cs.CS_MODE_32 | cs.CS_MODE_BIG_ENDIAN)
        md.detail = True
        insn = next(md.disasm(bytes.fromhex("80640008"), 0x1000))  # lwz r3, 8(r4)
        sw = Instruction.from_capstone(insn)
        mem = [o for o in insn.operands if o.type == cs.CS_OP_MEM][0]
        self.assertEqual(sw._memory_reference_operand(mem).base, "r4")


class SegmentAddressTests(unittest.TestCase):
    """`segment` has to reach the computed address. Needs no pyghidra."""

    class _Emu:
        """Just enough Emulator for address(): a platdef and registers."""

        def __init__(self, platdef, **regs):
            self.platdef = platdef
            self._regs = regs

        def read_register(self, name):
            return self._regs[name]

    @staticmethod
    def _platdef(arch, byteorder="LITTLE"):
        from smallworld.platforms import (
            Architecture,
            Byteorder,
            Platform,
            PlatformDef,
        )

        return PlatformDef.for_platform(
            Platform(Architecture[arch], Byteorder[byteorder])
        )

    def test_segment_base_is_added_to_the_address(self):
        """`fs:[0x28]` is fsbase+0x28. It used to resolve to 0x28: `segment`
        was carried on the operand and then read by nothing, so every address
        computed from a Capstone-produced segment operand was missing the
        segment base -- and the unmapped-access check in the Unicorn emulator
        ran on the wrong address."""
        from smallworld.instructions.bsid import BSIDMemoryReferenceOperand

        amd64 = self._platdef("X86_64")
        emu = self._Emu(amd64, fsbase=0x2000, gsbase=0x3000, rdx=4)

        fs = BSIDMemoryReferenceOperand(segment="fs", offset=0x28, size=8)
        self.assertEqual(fs.address(emu), 0x2028)

        gs = BSIDMemoryReferenceOperand(segment="gs", offset=0x13, size=8)
        self.assertEqual(gs.address(emu), 0x3013)

        # The segment base composes with an index rather than replacing it.
        indexed = BSIDMemoryReferenceOperand(
            segment="fs", index="rdx", scale=2, offset=8, size=8
        )
        self.assertEqual(indexed.address(emu), 0x2000 + 2 * 4 + 8)

        # No segment: unchanged.
        plain = BSIDMemoryReferenceOperand(index="rdx", offset=8, size=8)
        self.assertEqual(plain.address(emu), 12)

    def test_platform_without_a_segment_base_is_unchanged(self):
        """i386 models the fs/gs selectors but no base register, so there is
        nothing to add and the address must not raise looking for one."""
        from smallworld.instructions.bsid import BSIDMemoryReferenceOperand

        i386 = self._platdef("X86_32")
        emu = self._Emu(i386, ebx=0x40)
        fs = BSIDMemoryReferenceOperand(segment="fs", base="ebx", offset=8, size=4)
        self.assertEqual(fs.address(emu), 0x48)

    def test_emulator_without_a_platdef_is_tolerated(self):
        """`platdef` is not on the Emulator interface -- symbolic_address only
        reaches it behind a type: ignore -- so address() must degrade rather
        than raise for one that has none."""
        from smallworld.instructions.bsid import BSIDMemoryReferenceOperand

        class Bare:
            def read_register(self, name):
                return 0x10

        fs = BSIDMemoryReferenceOperand(segment="fs", offset=8, size=8)
        self.assertEqual(fs.address(Bare()), 8)

    def test_segment_survives_a_json_round_trip(self):
        """Now that `segment` moves the address, dropping it on serialization
        would silently relocate the access -- the same bug `size` had."""
        from smallworld.instructions.bsid import BSIDMemoryReferenceOperand

        op = BSIDMemoryReferenceOperand(segment="fs", offset=0x28, size=8)
        back = BSIDMemoryReferenceOperand.from_json(op.to_json())
        self.assertEqual(back.segment, "fs")
        self.assertEqual(back.address(self._Emu(self._platdef("X86_64"), fsbase=0x2000)), 0x2028)

        # A payload written before to_json emitted `segment` still loads.
        legacy = {"base": "rsp", "index": None, "scale": 1, "offset": -8, "size": 8}
        self.assertIsNone(BSIDMemoryReferenceOperand.from_json(legacy).segment)


class ThumbUseDefBackendTests(unittest.TestCase):
    """Thumb must not go through p-code. Needs no pyghidra: the refusal
    happens before the backend is reached."""

    def test_thumb_falls_back_to_capstone(self):
        from smallworld.instructions import Instruction, RegisterOperand
        from smallworld.platforms import Architecture, Byteorder, Platform

        platform = Platform(Architecture.ARM_V6M_THUMB, Byteorder.LITTLE)
        insn = Instruction.from_bytes(
            b"\x08\x46", 0x1000, platform, use_def_backend="pcode"
        )  # Thumb `mov r0, r1`; as ARM these bytes are andeq r0,r0,r6,lsl #16
        self.assertFalse(insn._use_pcode())
        self.assertEqual(insn.reads, {RegisterOperand("r1")})
        self.assertEqual(insn.writes, {RegisterOperand("r0")})


@unittest.skipUnless(HAVE_PYPCODE, "pypcode is not installed")
class AddressMaskingTests(unittest.TestCase):
    """The one approximation in the address walker, and its bound."""

    def test_alignment_mask_within_the_access_is_approximated(self):
        """MIPS lwl/lwr compute addr - (addr & 3) for a 4-byte access; the
        mask moves the address by less than the access, so dropping it keeps
        the operand inside the same access."""
        from smallworld.instructions import RegisterOperand
        from smallworld.instructions.pcode_use_def import analyze

        result = analyze(bytes.fromhex("88a40000"), "MIPS:BE:32:default", 0)  # lwl
        self.assertIsNotNone(result)
        mems = [o for o in result.uses if not isinstance(o, RegisterOperand)]
        self.assertTrue(mems, "lwl reported no memory operand")

    def test_mask_wider_than_the_access_raises(self):
        """Unbounded, the approximation rewrote real address arithmetic: a
        truncating `x & 0xffff` matched the "remainder bits" form and dropped
        the term, so base + (x & 0xffff) silently became base."""
        from smallworld.instructions.pcode_use_def import (
            _PCODE_OP,
            UseDefError,
            _flatten_sum,
        )

        class _Space:
            def __init__(self, name):
                self.name = name

        class _Const:
            """Stand-in for a constant varnode; _flatten_sum only asks these."""

            def __init__(self, value, size):
                self.offset, self.size = value, size
                self.space = _Space("const")

        class _Reg(_Const):
            def __init__(self, value, size):
                super().__init__(value, size)
                self.space = _Space("register")

        reg = _Reg(0, 4)
        # 0xffff spans far more than a 4-byte access: not approximable.
        with self.assertRaises(UseDefError):
            _flatten_sum((_PCODE_OP.INT_AND, [reg, _Const(0xFFFF, 4)]), 1, [], 4)
        # 3 is within a 4-byte access: still approximated, as MIPS lwl needs.
        terms = []
        _flatten_sum((_PCODE_OP.INT_AND, [reg, _Const(3, 4)]), 1, terms, 4)
        self.assertEqual(terms, [])
        # x & 0 is 0, not x -- the align-down test would once have claimed
        # the whole mask was a no-op, because (~0) & (~0 + 1) is 0 in
        # Python's unbounded ints.
        terms = []
        _flatten_sum((_PCODE_OP.INT_AND, [reg, _Const(0, 4)]), 1, terms, 4)
        self.assertEqual(terms, [])

    def test_indirect_branch_target_is_reported(self):
        """The register whose value is the destination, resolved through the
        symbolic state: Ghidra's MIPS jr is COPY t9 -> pc then BRANCHIND pc,
        masked by a computed ~1, so neither the raw varnode nor the address
        walker recovers t9."""
        from smallworld.instructions.pcode_use_def import analyze

        result = analyze(bytes.fromhex("03200008"), "MIPS:BE:32:default", 0)  # jr t9
        self.assertEqual(result.indirect_targets, ("t9",))

    def test_direct_branch_reports_no_indirect_target(self):
        from smallworld.instructions.pcode_use_def import analyze

        result = analyze(bytes.fromhex("11090004"), "MIPS:BE:32:default", 0)  # beq
        self.assertEqual(result.indirect_targets, ())


class InstructionFetchesTests(unittest.TestCase):
    """Instruction.fetches(): where control transfer will FETCH from.

    jr $t9 reads t9 but reads no data memory at [t9] -- the next
    instruction fetch does -- so the dereference lives here, not in
    `reads`. The Capstone-fallback cases run without pyghidra; the rest
    need it and skip cleanly.
    """

    @staticmethod
    def _insn(arch, byteorder, hexbytes, backend):
        from smallworld.instructions import Instruction
        from smallworld.platforms import Architecture, Byteorder, Platform

        return Instruction.from_bytes(
            bytes.fromhex(hexbytes),
            0x1000,
            Platform(Architecture[arch], Byteorder[byteorder]),
            use_def_backend=backend,
        )

    @staticmethod
    def _bases(operands):
        return {op.base for op in operands if hasattr(op, "base")}

    @unittest.skipUnless(HAVE_PYPCODE, "pypcode is not installed")
    def test_indirect_transfers_report_their_target(self):
        from smallworld.instructions import RegisterOperand

        for arch, bo, hexbytes, desc, target in (
            ("MIPS32", "BIG", "03200008", "jr $t9", "t9"),
            ("MIPS32", "BIG", "0320f809", "jalr $t9", "t9"),
            ("X86_64", "LITTLE", "ffe0", "jmp rax", "rax"),
            ("ARM_V7A", "LITTLE", "1eff2fe1", "bx lr", "lr"),
        ):
            with self.subTest(instruction=desc):
                insn = self._insn(arch, bo, hexbytes, "pcode")
                self.assertEqual(self._bases(insn.fetches()), {target})
                # The register read stays a read; the dereference does NOT
                # appear there (it is a fetch, not a data read).
                self.assertIn(RegisterOperand(target), insn.reads)
                self.assertNotIn(target, self._bases(insn.reads))

    @unittest.skipUnless(HAVE_PYPCODE, "pypcode is not installed")
    def test_non_transfers_and_popped_targets_fetch_nothing(self):
        # Not a branch at all.
        self.assertEqual(
            self._insn("X86_64", "LITTLE", "4801d8", "pcode").fetches(), set()
        )
        # ret's target is popped off the stack: the pop is already a data
        # read ([rsp] in reads); the target's VALUE names no register, so
        # there is no fetch operand to build.
        ret = self._insn("X86_64", "LITTLE", "c3", "pcode")
        self.assertEqual(ret.fetches(), set())
        self.assertIn("rsp", self._bases(ret.reads))
        # Same for a memory-indirect jmp: the pointer load is the read.
        self.assertEqual(
            self._insn("X86_64", "LITTLE", "ff20", "pcode").fetches(), set()
        )

    def test_capstone_fallback_uses_the_mnemonic_lists(self):
        insn = self._insn("MIPS32", "BIG", "03200008", "capstone")  # jr $t9
        self.assertEqual(self._bases(insn.fetches()), {"t9"})
        # ...and its reads no longer substitute the dereference for the
        # register, so the two backends agree.
        from smallworld.instructions import RegisterOperand

        self.assertIn(RegisterOperand("t9"), insn.reads)

    def test_capstone_fallback_unlisted_mnemonic_fetches_nothing(self):
        insn = self._insn("MIPS32", "BIG", "8fa80004", "capstone")  # lw
        self.assertEqual(insn.fetches(), set())


@unittest.skipUnless(HAVE_PYPCODE, "pypcode is not installed")
class UseDefCorpusTests(unittest.TestCase):
    """Every corpus entry must agree with ground truth (normalized)."""

    #: Floor for entries matching ground truth *strictly* (no normalization).
    #: 599 of 794 as of this commit. A floor rather than an equality so that
    #: improving the analysis does not fail the suite -- raise it when it
    #: climbs.
    MIN_STRICT_MATCHES = 599

    def test_corpus(self):
        from smallworld.instructions.pcode_use_def import analyze

        harness = _load_corpus_harness()
        corpora = harness.load_corpora(HERE, None)
        self.assertTrue(corpora, f"no corpus files found in {HERE}")
        strict = 0
        total = 0
        for corpus in corpora:
            with self.subTest(isa=corpus["isa"]):
                disagreements = []
                for entry in corpus["entries"]:
                    result = harness.check_entry(entry, corpus, analyze)
                    total += 1
                    if result["status"] == "pass":
                        strict += 1
                    if result["status"] not in ("pass", "pass-normalized"):
                        detail = result.get("error") or (
                            f"missing use={result.get('missing_use_norm')} "
                            f"extra use={result.get('extra_use_norm')} "
                            f"missing def={result.get('missing_def_norm')} "
                            f"extra def={result.get('extra_def_norm')}"
                        )
                        disagreements.append(
                            f"[{result['status']}] {result['asm']}: {detail}"
                        )
                self.assertEqual(
                    disagreements,
                    [],
                    f"{corpus['isa']}: {len(disagreements)} of "
                    f"{len(corpus['entries'])} entries disagree",
                )

        # Agreement above accepts "pass-normalized", and normalizing drops
        # flag and pc registers from BOTH sides before comparing -- so an
        # analysis that stopped reporting x86 flags entirely would still show
        # 100% agreement. Hold the number of *strict* matches at or above
        # where it stands, which is the part normalization cannot hide.
        self.assertGreaterEqual(
            strict,
            self.MIN_STRICT_MATCHES,
            msg=f"strict corpus matches fell to {strict}/{total} (floor is "
            f"{self.MIN_STRICT_MATCHES}); entries still agree once flag and "
            f"pc registers are normalized away, so something changed how "
            f"operands are named or which are reported",
        )


@unittest.skipUnless(HAVE_PYPCODE, "pypcode is not installed")
class InstructionUseDefTests(unittest.TestCase):
    """Instruction.reads/.writes: sets of platform-valid Operands.

    These assert the pcode analysis's output specifically, so they ask for the
    pcode backend -- Capstone is the default until the changeover PR.
    """

    # (arch, byteorder, hex, description, must_read, must_write). The last
    # two are a deliberate *subset* -- flags left out, so adding one to a
    # platform definition later does not break these -- and exist to catch
    # operands going missing, which an "is it a set?" check cannot.
    SAMPLES = [
        ("X86_64", "LITTLE", "4801d8", "add rax, rbx", {"rax", "rbx"}, {"rax"}),
        ("X86_64", "LITTLE", "89cb", "mov ebx, ecx", {"ecx"}, {"ebx"}),
        ("X86_64", "LITTLE", "50", "push rax", {"rax", "rsp"}, {"rsp"}),
        (
            "X86_64",
            "LITTLE",
            "488b448a10",
            "mov rax, [rdx+rcx*4+16]",
            {"rcx", "rdx"},
            {"rax"},
        ),
        ("X86_64", "LITTLE", "f20f104308", "movsd xmm0, [rbx+8]", {"rbx"}, {"xmm0"}),
        ("X86_64", "LITTLE", "488b042500100000", "mov rax, [0x1000]", set(), {"rax"}),
        # The stack-protector read. SLEIGH flattens the segment reference into
        # an add against FS_OFFSET, so the whole operand went missing before
        # the fsbase alias and then lost its `segment` before the fold.
        (
            "X86_64",
            "LITTLE",
            "64488b042528000000",
            "mov rax, fs:[0x28]",
            {"fsbase"},
            {"rax"},
        ),
        ("X86_32", "LITTLE", "50", "push eax", {"eax", "esp"}, {"esp"}),
        ("X86_32", "LITTLE", "8b4c2408", "mov ecx, [esp+8]", {"esp"}, {"ecx"}),
        ("POWERPC32", "BIG", "9421ffd0", "stwu r1, -0x30(r1)", {"r1"}, {"r1"}),
        ("POWERPC32", "BIG", "7c641b79", "mr. r4, r3", {"r3"}, {"r4"}),
        ("POWERPC32", "BIG", "7ca6282e", "lwzx r5, r6, r5", {"r5", "r6"}, {"r5"}),
        ("AARCH64", "LITTLE", "200440f9", "ldr x0, [x1, #8]", {"x1"}, {"x0"}),
        ("AARCH64", "LITTLE", "20040039", "strb w0, [x1, #1]", {"w0", "x1"}, set()),
        ("MIPS32", "BIG", "8fa80004", "lw t0, 4(sp)", {"sp"}, {"t0"}),
        ("MIPS32", "BIG", "01090018", "mult t0, t1", {"t0", "t1"}, {"hi0", "lo0"}),
        ("MIPS32", "LITTLE", "0400a88f", "lw t0, 4(sp) (mipsel)", {"sp"}, {"t0"}),
        # MIPS64 both endiannesses -- little-endian is the case that used to
        # decode as big-endian and yield empty operands.
        ("MIPS64", "BIG", "00a6202d", "daddu a0, a1, a2", {"a1", "a2"}, {"a0"}),
        (
            "MIPS64",
            "LITTLE",
            "2d20a600",
            "daddu a0, a1, a2 (mips64el)",
            {"a1", "a2"},
            {"a0"},
        ),
        ("MIPS64", "LITTLE", "0800a4df", "ld a0, 8(sp) (mips64el)", {"sp"}, {"a0"}),
        # 32-bit ops on MIPS64: Ghidra reports the <reg>_lo views, which used
        # to be dropped wholesale -- these reported NO operands at all.
        ("MIPS64", "BIG", "00a62021", "addu a0, a1, a2 (32-bit)", {"a1", "a2"}, {"a0"}),
        ("MIPS64", "BIG", "00a60018", "mult a1, a2", {"a1", "a2"}, {"hi0", "lo0"}),
        # The O32/N64 collision: Ghidra disassembles this as `addu t4,t0,t1`
        # ($12,$8,$9), which N64 names t0,a4,a5. Passing Ghidra's names
        # through unchanged silently named three different registers.
        (
            "MIPS64",
            "BIG",
            "01096021",
            "addu $12, $8, $9 (O32/N64)",
            {"a4", "a5"},
            {"t0"},
        ),
        # ARM-mode (little-endian bytes); routed through pcode via the
        # platform's ghidra_language_id (ARM:LE:32:v7).
        ("ARM_V7A", "LITTLE", "081092e5", "ldr r1, [r2, #8]", {"r2"}, {"r1"}),
        (
            "ARM_V7A",
            "LITTLE",
            "70402de9",
            "push {r4, r5, r6, lr}",
            {"lr", "r4", "r5", "r6", "sp"},
            {"sp"},
        ),
        ("ARM_V7A", "LITTLE", "1eff2fe1", "bx lr", {"lr"}, {"pc"}),
        # Condition flags reach the platform's status register. The corpus
        # checks these in Ghidra's namespace (ng/zr/cy/ov); only here does
        # the mapping onto cpsr/nzcv get exercised.
        ("ARM_V7A", "LITTLE", "010050e1", "cmp r0, r1", {"r0", "r1"}, {"cpsr"}),
        ("ARM_V7A", "LITTLE", "0110a0e0", "adc r1, r0, r1", {"cpsr", "r0"}, {"r1"}),
        ("AARCH64", "LITTLE", "1f0001eb", "cmp x0, x1", {"x0", "x1"}, {"nzcv"}),
        ("AARCH64", "LITTLE", "2000019a", "adc x0, x1, x1", {"nzcv", "x1"}, {"x0"}),
        ("AARCH64", "LITTLE", "20049f9a", "cset x0, eq", {"nzcv"}, {"x0"}),
    ]

    def test_reads_writes_are_platform_valid(self):
        from smallworld.instructions import Instruction, RegisterOperand
        from smallworld.platforms import (
            Architecture,
            Byteorder,
            Platform,
            PlatformDef,
        )

        for arch, bo, hexbytes, desc, must_read, must_write in self.SAMPLES:
            with self.subTest(instruction=desc):
                platform = Platform(Architecture[arch], Byteorder[bo])
                platdef = PlatformDef.for_platform(platform)
                insn = Instruction.from_bytes(
                    bytes.fromhex(hexbytes),
                    0x1000,
                    platform,
                    use_def_backend="pcode",
                )
                for kind, operands in (("reads", insn.reads), ("writes", insn.writes)):
                    self.assertIsInstance(operands, set)
                    # Every name check below lives inside a loop over
                    # `operands`, so without this an empty set would satisfy
                    # them all vacuously -- and an operand silently dropped by
                    # the naming layer is exactly how this analysis fails.
                    self.assertTrue(
                        operands, msg=f"{desc}: {kind} is empty for {platform}"
                    )
                    for op in operands:
                        if isinstance(op, RegisterOperand):
                            self.assertIn(op.name, platdef.registers)
                        else:
                            for attr in ("base", "index"):
                                name = getattr(op, attr, None)
                                if name is not None:
                                    self.assertIn(name, platdef.registers)

                for kind, operands, expected in (
                    ("reads", insn.reads, must_read),
                    ("writes", insn.writes, must_write),
                ):
                    got = {
                        op.name for op in operands if isinstance(op, RegisterOperand)
                    }
                    self.assertLessEqual(
                        expected,
                        got,
                        msg=f"{desc}: {kind} lost {sorted(expected - got)} "
                        f"(reported {sorted(got)})",
                    )

    def test_push_semantics(self):
        from smallworld.instructions import Instruction, RegisterOperand
        from smallworld.platforms import Architecture, Byteorder, Platform

        platform = Platform(Architecture.X86_64, Byteorder.LITTLE)
        insn = Instruction.from_bytes(
            b"\x50", 0x1000, platform, use_def_backend="pcode"
        )  # push rax
        self.assertEqual(insn.reads, {RegisterOperand("rax"), RegisterOperand("rsp")})
        mems = [op for op in insn.writes if not isinstance(op, RegisterOperand)]
        self.assertEqual(len(mems), 1)
        self.assertEqual(mems[0].base, "rsp")
        self.assertEqual(mems[0].offset, -8)
        self.assertEqual(mems[0].size, 8)
        self.assertIn(RegisterOperand("rsp"), insn.writes)

    def test_flags_collapse_to_rflags(self):
        from smallworld.instructions import Instruction, RegisterOperand
        from smallworld.platforms import Architecture, Byteorder, Platform

        platform = Platform(Architecture.X86_64, Byteorder.LITTLE)
        insn = Instruction.from_bytes(
            b"\x48\x01\xd8", 0x1000, platform, use_def_backend="pcode"
        )
        self.assertEqual(
            insn.writes, {RegisterOperand("rax"), RegisterOperand("rflags")}
        )


class UseDefBackendSelectionTests(unittest.TestCase):
    """reads/writes backend selection: Capstone default, pcode opt-in.

    The Capstone path needs no pyghidra, so these run unconditionally.
    """

    def _insn(self, **kwargs):
        from smallworld.instructions import Instruction
        from smallworld.platforms import Architecture, Byteorder, Platform

        # push rax -- exercises implicit rsp + a stack memory operand,
        # which the two backends spell differently (pcode resolves the
        # address pre-execution as [rsp-8]; Capstone reports [rsp]).
        return Instruction.from_bytes(
            b"\x50", 0x1000, Platform(Architecture.X86_64, Byteorder.LITTLE), **kwargs
        )

    def test_capstone_backend_needs_no_sleigh(self):
        from smallworld.instructions import BSIDMemoryReferenceOperand, RegisterOperand

        insn = self._insn(use_def_backend="capstone")
        self.assertFalse(insn._use_pcode())
        self.assertIn(RegisterOperand("rsp"), insn.reads)
        mems = [op for op in insn.writes if isinstance(op, BSIDMemoryReferenceOperand)]
        self.assertEqual(len(mems), 1)
        self.assertEqual(mems[0].base, "rsp")

    def test_default_backend_is_pcode(self):
        insn = self._insn()
        self.assertEqual(insn.use_def_backend, "pcode")
        # ...and actually used, because its engine is a core dependency.
        # This gate was written against pyghidra, which was an optional
        # extra; asserting that here would now pass only where pyghidra
        # happens to be installed anyway and fail on the base install this
        # backend is meant to work on. _use_pcode probes availability, it
        # does not import.
        import importlib.util

        self.assertEqual(
            insn._use_pcode(),
            importlib.util.find_spec("pypcode") is not None,
        )

    def test_unknown_backend_rejected(self):
        with self.assertRaises(ValueError):
            self._insn(use_def_backend="nope")

    @unittest.skipUnless(HAVE_PYPCODE, "pypcode is not installed")
    def test_pcode_and_capstone_agree_on_push_address(self):
        # Both backends must resolve push rax's write to the same stack
        # slot, even though they spell the operand differently.
        from smallworld.instructions import BSIDMemoryReferenceOperand

        class _Regs:
            def read_register(self, name):
                return 0x7FFF_0000 if name == "rsp" else 0

        emu = _Regs()

        pcode_mem = next(
            op
            for op in self._insn(use_def_backend="pcode").writes
            if isinstance(op, BSIDMemoryReferenceOperand)
        )
        cap_mem = next(
            op
            for op in self._insn(use_def_backend="capstone").writes
            if isinstance(op, BSIDMemoryReferenceOperand)
        )
        # pcode: [rsp-8] resolved pre-execution; Capstone: [rsp] meant
        # to be read post-decrement. Against the same pre-push rsp they
        # differ by the push width -- documenting, not asserting equal.
        self.assertEqual(pcode_mem.address(emu), 0x7FFF_0000 - 8)
        self.assertEqual(cap_mem.address(emu), 0x7FFF_0000)


@unittest.skipUnless(HAVE_PYPCODE, "pypcode is not installed")
class ForkSafetyTests(unittest.TestCase):
    """Analysis must survive the caller forking.

    multiprocessing's default start method on Linux is `fork` through CPython
    3.13, so `ProcessPoolExecutor().map(...)` around an analysis forks a
    process that has already analyzed. On pyghidra that deadlocked the child:
    a fork inherits the JVM's mutexes but not the threads holding them, so
    the first JNI call blocked forever, immune even to SIGTERM. The order
    below is the one that reproduced it.

    Children are joined with a timeout and killed, so a regression fails the
    test rather than wedging CI.
    """

    LANG = "x86:LE:64:default"
    TIMEOUT = 120

    @staticmethod
    def _child(q):
        # Deliberately bytes the parent has NOT analyzed, so the child cannot
        # be served from the result cache it inherited and must translate.
        from smallworld.instructions.pcode_use_def import analyze

        try:
            result = analyze(bytes.fromhex("4831d8"), ForkSafetyTests.LANG, 0x3000)
            q.put(len(result.uses))
        except BaseException as e:  # noqa: BLE001 - reported through the queue
            q.put(f"{type(e).__name__}: {e}")

    def _fork_and_analyze(self, label):
        ctx = multiprocessing.get_context("fork")
        q = ctx.Queue()
        proc = ctx.Process(target=self._child, args=(q,))
        proc.start()
        proc.join(self.TIMEOUT)
        if proc.is_alive():
            proc.kill()
            proc.join()
            self.fail(f"{label}: forked child hung for {self.TIMEOUT}s")
        self.assertFalse(q.empty(), f"{label}: child produced no result")
        self.assertEqual(q.get(), 2, f"{label}: child analyzed incorrectly")

    def test_analysis_works_in_a_child_forked_after_the_parent_analyzed(self):
        from smallworld.instructions.pcode_use_def import analyze

        self._fork_and_analyze("before the parent analyzed anything")
        self.assertIsNotNone(analyze(bytes.fromhex("4801d8"), self.LANG, 0x2000))
        self._fork_and_analyze("after the parent analyzed")

    def test_analysis_loads_no_jvm(self):
        """The deadlock above is a symptom; this asserts the cause.

        In a FRESH interpreter, because sibling tests here boot a JVM
        deliberately -- asserting on this process would measure test ordering.
        """
        if not sys.platform.startswith("linux"):
            self.skipTest("needs /proc/self/maps")
        program = textwrap.dedent("""
            from smallworld.instructions.pcode_use_def import analyze
            assert analyze(bytes.fromhex("4801d8"), "x86:LE:64:default", 0) is not None
            with open("/proc/self/maps") as fh:
                hits = [ln for ln in fh if "libjvm" in ln or "jpype" in ln]
            print(len(hits))
            """)
        proc = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True,
            text=True,
            timeout=self.TIMEOUT,
        )
        self.assertEqual(proc.returncode, 0, f"probe failed: {proc.stderr[-500:]}")
        self.assertEqual(
            proc.stdout.strip(),
            "0",
            "a p-code analysis pulled a JVM into a fresh process",
        )


if __name__ == "__main__":
    unittest.main()
