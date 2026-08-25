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

These boot Ghidra's JVM via pyghidra on first use and take a couple of
minutes for the full corpus; they skip cleanly when pyghidra is not
installed.
"""

import importlib
import importlib.util
import os
import sys
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
        # x86-64 segment addressing reads a real FS_OFFSET register that no
        # platform definition models: the whole reference has to go, since
        # without a base there is no address to compute.
        unresolvable = BSIDMemoryReferenceOperand(base="fs_offset", offset=0x28, size=8)
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
        """Boot the JVM through the analysis module rather than calling
        pyghidra.start() directly.

        Ghidra discovers extensions only while its Application initializes,
        during the first pyghidra.start() in the process, so whichever test
        starts the JVM has to prepare the SymZ3 extension first or every later
        GhidraSymbolicEmulator in the same process fails to resolve its
        classes. _ensure_pyghidra() is exactly that sequence.
        """
        from smallworld.instructions.pcode_use_def import _ensure_pyghidra

        _ensure_pyghidra()

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


@unittest.skipUnless(HAVE_PYGHIDRA, "pyghidra is not installed")
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

    def test_op_table_covers_every_ghidra_mnemonic(self):
        """The op table is an allowlist keyed by Ghidra's mnemonic strings, so
        it silently rots against a new Ghidra. Compare it to the real table."""
        from smallworld.instructions.pcode_use_def import _ensure_pyghidra

        _ensure_pyghidra()  # boots the JVM, preparing the SymZ3 extension first
        from ghidra.program.model.pcode import PcodeOp  # type: ignore

        from smallworld.instructions.pcode_use_def import _PCODE_OP

        ghidra_names = set()
        for opcode in range(PcodeOp.PCODE_MAX):
            try:
                ghidra_names.add(str(PcodeOp.getMnemonic(opcode)))
            except Exception:
                continue
        self.assertTrue(ghidra_names, "could not read Ghidra's mnemonic table")
        missing = sorted(ghidra_names - {m.name for m in _PCODE_OP})
        self.assertEqual(
            missing,
            [],
            msg=f"_PCODE_OP is missing mnemonics Ghidra emits: {missing}. "
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

    def test_failed_decode_is_not_memoized(self):
        """_pcode_use_def turns None into an empty use/def set, so a cached
        None would report an instruction as a no-op for the whole process."""
        from smallworld.instructions.pcode_use_def import analyze

        analyze.cache_clear()
        undecodable = b"\xff\xff\xff\xff"
        self.assertIsNone(analyze(undecodable, "MIPS:BE:32:default", 0))
        self.assertIsNone(analyze(undecodable, "MIPS:BE:32:default", 0))
        self.assertEqual(analyze.cache_info().currsize, 0, "a failed decode was cached")

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

    Needs no pyghidra: analyze is replaced, and pcode_use_def imports pyghidra
    lazily (inside _ensure_pyghidra) precisely so this is true -- a top-level
    import made this class ERROR rather than run on a base install, and
    tests/unit.py imports it into the main suite.
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
            with self.assertLogs(instructions_mod.logger, level="WARNING") as logs:
                self.assertEqual(insn.reads, set())
                self.assertEqual(insn.writes, set())
        finally:
            pcode_use_def.analyze = real
        self.assertTrue(any("synthetic" in line for line in logs.output))

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
            bytes.fromhex("8fa80004"), 0x1000, platform
        )  # lw t0, 4(sp); default backend is Capstone

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

        # reads legitimately needs it (implicit_dereference_mnemonics).
        self.assertTrue(insn.reads)


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


@unittest.skipUnless(HAVE_PYGHIDRA, "pyghidra is not installed")
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

        class _Const:
            """Stand-in for a constant varnode; _flatten_sum only asks these."""

            def __init__(self, value, size):
                self._value, self._size = value, size

            def getSize(self):
                return self._size

            def getOffset(self):
                return self._value

            def isConstant(self):
                return True

        class _Reg(_Const):
            def isConstant(self):
                return False

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


@unittest.skipUnless(HAVE_PYGHIDRA, "pyghidra is not installed")
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


@unittest.skipUnless(HAVE_PYGHIDRA, "pyghidra is not installed")
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

    def test_capstone_backend_needs_no_pyghidra(self):
        from smallworld.instructions import BSIDMemoryReferenceOperand, RegisterOperand

        insn = self._insn(use_def_backend="capstone")
        self.assertFalse(insn._use_pcode())
        self.assertIn(RegisterOperand("rsp"), insn.reads)
        mems = [op for op in insn.writes if isinstance(op, BSIDMemoryReferenceOperand)]
        self.assertEqual(len(mems), 1)
        self.assertEqual(mems[0].base, "rsp")

    def test_default_backend_is_capstone(self):
        # Capstone remains the default until the changeover PR, regardless
        # of whether pyghidra is available.
        insn = self._insn()
        self.assertEqual(insn.use_def_backend, "capstone")
        self.assertFalse(insn._use_pcode())

    def test_unknown_backend_rejected(self):
        with self.assertRaises(ValueError):
            self._insn(use_def_backend="nope")

    @unittest.skipUnless(HAVE_PYGHIDRA, "pyghidra is not installed")
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


if __name__ == "__main__":
    unittest.main()
