from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_assert_contains

NATIVE_PARITY = True

# Triton's CPU models cover integer and control flow only: it reports x87/SSE
# and AArch64 FP instructions as undefined, and Triton's ARM32 target does not
# expose the VFP registers at all. The variants are listed so the gap is
# visible; drop the reason if Triton ever grows floating-point semantics.
_TRITON_NO_FLOAT = "Triton implements no floating-point instruction semantics"

_SH4_ANGR_PR = (
    "SH-4's sleigh takes precision from FPSCR_PR, which SmallWorld cannot set "
    "and angr leaves unconstrained, so fadd forks; with it set, angr's p-code "
    "engine still cannot take fadd's branch on it"
)

_VARIANTS = (
    ("aarch64", None),
    ("aarch64.angr", None),
    ("aarch64.pcode", None),
    ("aarch64.triton", _TRITON_NO_FLOAT),
    ("amd64", None),
    ("amd64.angr", None),
    ("amd64.pcode", None),
    ("amd64.triton", _TRITON_NO_FLOAT),
    ("armhf.angr", None),
    ("armhf.pcode", None),
    ("armhf.triton", _TRITON_NO_FLOAT),
    ("i386", None),
    ("i386.angr", None),
    ("i386.pcode", None),
    ("i386.triton", _TRITON_NO_FLOAT),
    ("ppc", None),
    ("ppc.angr", None),
    ("ppc.pcode", None),
    ("ppc64", None),
    ("ppc64.angr", None),
    ("ppc64.pcode", None),
    # SuperH selects precision from FPSCR rather than the opcode, so these run
    # single-precision with PR=0; 2.2 + 1.1 comes out as 3.3000002, which still
    # carries the "3.3" this scenario asserts on.  Double precision is broken on
    # Styx for SuperH, so it stays out of reach here.
    ("sh2a.pcode", None),
    ("sh2a.angr", None),
    ("sh2a.styx", None),
    # SH-4's sleigh reads precision from FPSCR_PR, a register of its own that
    # only `lds Rm,FPSCR` refreshes, and SmallWorld cannot set it.  Ghidra
    # starts it at 0, single precision; angr leaves it unconstrained, so `fadd`
    # forks into its single- and double-precision paths.  Were it set, angr
    # would still fail: its p-code engine cannot branch within an instruction
    # (see testfloat_arch/superh.py).
    ("sh4.pcode", None),
    ("sh4.angr", _SH4_ANGR_PR),
    ("sh4el.pcode", None),
    ("sh4el.angr", _SH4_ANGR_PR),
    # V850E2M's FPU, which works on the general registers.
    ("v850.pcode", None),
    ("v850.angr", None),
)

SCENARIO_INFO = ScenarioInfo(
    prefix="floats",
    scenario="floats",
    tags=("scenario", "floats"),
    variants_source=from_variants(_VARIANTS),
    run_factory=script_assert_contains(
        "3.3",
        script_template="floats/floats.{variant}.py",
        args=("2.2", "1.1"),
    ),
)
