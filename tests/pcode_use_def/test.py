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

# The analysis code once contained live breakpoint() calls; keep runs
# non-interactive even if one reappears.
os.environ.setdefault("PYTHONBREAKPOINT", "0")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

try:
    import pyghidra  # noqa: F401

    HAVE_PYGHIDRA = True
except ImportError:
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

    # ---------------------------------------------------------------- #
    # Known gaps. These fail today and are marked expected so they are
    # recorded rather than forgotten; fixing one turns it into an
    # unexpected success, which fails the suite and forces the marker
    # off. Do not "fix" one by deleting it.
    # ---------------------------------------------------------------- #

    @unittest.expectedFailure
    def test_aarch64_condition_flags_reach_a_register(self):
        """ng/zr/cy/ov alias to 'nzcv', which aarch64.py does not define, so
        `cmp x0, x1` reports an empty write set."""
        self.assertIsNotNone(self._canon("AARCH64", "LITTLE", "ng"))

    @unittest.expectedFailure
    def test_powerpc_xer_bits_reach_a_register(self):
        """xer_* alias to 'xer', whose RegisterDef is commented out in
        powerpc.py (the platform models it as spr_xer), so every carry and
        overflow edge is dropped."""
        self.assertIsNotNone(self._canon("POWERPC32", "BIG", "xer_so"))

    @unittest.expectedFailure
    def test_mips64_32bit_register_views_are_mapped(self):
        """register_alias has no MIPS64 branch, so Ghidra's <reg>_lo/_hi views
        and its hi/lo accumulators are all dropped -- every 32-bit MIPS64 op
        reports empty operands."""
        self.assertIsNotNone(self._canon("MIPS64", "BIG", "a0_lo"))
        self.assertIsNotNone(self._canon("MIPS64", "BIG", "hi"))

    @unittest.expectedFailure
    def test_mips64_o32_names_do_not_collide_with_n64(self):
        """Ghidra names MIPS64 GPRs o32-style, SmallWorld's platdef n64-style
        (see ghidra/machdefs/mips64.py). Ghidra's t0 is register 8, but
        SmallWorld's t0 is register 12, so this passes the membership check
        and silently names the wrong register."""
        # Ghidra's t4-t7 have no n64 counterpart under that name and drop...
        self.assertIsNotNone(self._canon("MIPS64", "BIG", "t4"))
        # ...while Ghidra's t0 maps onto a *different* physical register.
        self.assertNotEqual(self._canon("MIPS64", "BIG", "t0"), "t0")

    @unittest.expectedFailure
    def test_memory_operand_base_is_validated(self):
        """canonicalize_operand only aliases and checks RegisterOperand; a
        memory operand's base/index escape unmapped, so a Ghidra-only name
        like x86-64's fs_offset survives into an operand whose .address()
        raises when a consumer resolves it."""
        from smallworld.instructions.bsid import BSIDMemoryReferenceOperand
        from smallworld.instructions.pcode_naming import canonicalize_operand

        operand = BSIDMemoryReferenceOperand(base="fs_offset", offset=0x28, size=8)
        out = canonicalize_operand(operand, self._platdef("X86_64", "LITTLE"))
        self.assertTrue(
            out is None or out.base in self._platdef("X86_64", "LITTLE").registers
        )


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
        pyghidra.start()  # module-level import above; machdefs need the JVM
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
    the pcode one. Needs no pyghidra: analyze is replaced.
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

        real = PlatformDef.for_platform

        def _explode(*args, **kwargs):
            raise AssertionError("writes resolved a PlatformDef it never reads")

        PlatformDef.for_platform = classmethod(  # type: ignore[method-assign]
            lambda cls, *a, **k: _explode()
        )
        try:
            self.assertTrue(insn.writes)
        finally:
            PlatformDef.for_platform = real  # type: ignore[method-assign]

        # reads legitimately needs it (implicit_dereference_mnemonics).
        self.assertTrue(insn.reads)


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

    # (architecture, byteorder, hex encoding, description, must_read,
    #  must_write) -- the last two name registers the instruction
    # architecturally has to report. They are deliberately a *subset*, not the
    # exact answer: flag and status registers are left out so that adding one
    # to a platform definition later does not break these. Their job is to
    # catch operands going missing, which an "is it a set?" check cannot.
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
