"""Unit tests for the pcode-based instruction use/def analysis.

Two layers are covered:

* UseDefCorpusTests — regression over the validation corpus in this
  directory (see README.md): every entry must agree with hand-written
  ground truth at least under the harness's normalized comparison.

* InstructionUseDefTests — the consumer-facing Instruction.reads /
  .writes API: results must be sets of Operand objects whose register
  names exist in the SmallWorld platform definition (so they can be
  concretized against an emulator), with spot checks of exact semantics.

These boot Ghidra's JVM via pyghidra on first use and take a couple of
minutes for the full corpus; they skip cleanly when pyghidra is not
installed.
"""

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
        "use_def_corpus_harness", os.path.join(HERE, "harness.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(HAVE_PYGHIDRA, "pyghidra is not installed")
class UseDefCorpusTests(unittest.TestCase):
    """Every corpus entry must agree with ground truth (normalized)."""

    def test_corpus(self):
        from smallworld.instructions.instr_use_def import analyze_bytes

        harness = _load_corpus_harness()
        corpora = harness.load_corpora(HERE, None)
        self.assertTrue(corpora, f"no corpus files found in {HERE}")
        for corpus in corpora:
            with self.subTest(isa=corpus["isa"]):
                disagreements = []
                for entry in corpus["entries"]:
                    result = harness.check_entry(entry, corpus, analyze_bytes)
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


@unittest.skipUnless(HAVE_PYGHIDRA, "pyghidra is not installed")
class InstructionUseDefTests(unittest.TestCase):
    """Instruction.reads/.writes: sets of platform-valid Operands."""

    # (architecture, byteorder, hex encoding, description)
    SAMPLES = [
        ("X86_64", "LITTLE", "4801d8", "add rax, rbx"),
        ("X86_64", "LITTLE", "89cb", "mov ebx, ecx"),
        ("X86_64", "LITTLE", "50", "push rax"),
        ("X86_64", "LITTLE", "488b448a10", "mov rax, [rdx+rcx*4+16]"),
        ("X86_64", "LITTLE", "f20f104308", "movsd xmm0, [rbx+8]"),
        ("X86_64", "LITTLE", "488b042500100000", "mov rax, [0x1000]"),
        ("X86_32", "LITTLE", "50", "push eax"),
        ("X86_32", "LITTLE", "8b4c2408", "mov ecx, [esp+8]"),
        ("POWERPC32", "BIG", "9421ffd0", "stwu r1, -0x30(r1)"),
        ("POWERPC32", "BIG", "7c641b79", "mr. r4, r3"),
        ("POWERPC32", "BIG", "7ca6282e", "lwzx r5, r6, r5"),
        ("AARCH64", "LITTLE", "200440f9", "ldr x0, [x1, #8]"),
        ("AARCH64", "LITTLE", "20040039", "strb w0, [x1, #1]"),
        ("MIPS32", "BIG", "8fa80004", "lw t0, 4(sp)"),
        ("MIPS32", "BIG", "01090018", "mult t0, t1"),
    ]

    def test_reads_writes_are_platform_valid(self):
        from smallworld.instructions import Instruction, RegisterOperand
        from smallworld.platforms import (
            Architecture,
            Byteorder,
            Platform,
            PlatformDef,
        )

        for arch, bo, hexbytes, desc in self.SAMPLES:
            with self.subTest(instruction=desc):
                platform = Platform(Architecture[arch], Byteorder[bo])
                platdef = PlatformDef.for_platform(platform)
                insn = Instruction.from_bytes(bytes.fromhex(hexbytes), 0x1000, platform)
                for operands in (insn.reads, insn.writes):
                    self.assertIsInstance(operands, set)
                    for op in operands:
                        if isinstance(op, RegisterOperand):
                            self.assertIn(op.name, platdef.registers)
                        else:
                            for attr in ("base", "index"):
                                name = getattr(op, attr, None)
                                if name is not None:
                                    self.assertIn(name, platdef.registers)

    def test_push_semantics(self):
        from smallworld.instructions import Instruction, RegisterOperand
        from smallworld.platforms import Architecture, Byteorder, Platform

        platform = Platform(Architecture.X86_64, Byteorder.LITTLE)
        insn = Instruction.from_bytes(b"\x50", 0x1000, platform)  # push rax
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
        insn = Instruction.from_bytes(b"\x48\x01\xd8", 0x1000, platform)
        self.assertEqual(
            insn.writes, {RegisterOperand("rax"), RegisterOperand("rflags")}
        )


if __name__ == "__main__":
    unittest.main()
