from __future__ import annotations

from .common import TRITON_ARCHS
from .spec import ScenarioInfo, from_variants, script_assert_outputs

NATIVE_PARITY = True

_ARCHS = (
    "aarch64",
    "amd64",
    "armel",
    "armhf",
    "i386",
    "la64",
    "mips",
    "mipsel",
    "mips64",
    "mips64el",
    "ppc",
    "ppc64",
    "riscv64",
    # SuperH's `trapa #imm` reaches hook_syscall(s) only because
    # `machdefs/superh.py` and `machdefs/superh4.py` rewrite it into an
    # Ijk_Sys_syscall; sleigh p-code has no syscall opcode, so angr's pcode
    # lifter cannot produce that jumpkind on its own.  Xtensa below is the
    # same arrangement for the same reason.  These rows come out angr-only:
    # Triton has no SuperH or Xtensa target, and on PANDA the very same
    # instruction is an interrupt instead, which is what the `interrupt`
    # scenario covers.
    "sh2a",
    "sh4",
    "sh4el",
    "xtensa",
)

# angr and Triton are the two backends that implement syscall hooking; Triton
# covers the architectures it has a target for.
_VARIANTS = tuple((f"{arch}.angr", None) for arch in _ARCHS) + tuple(
    (f"{arch}.triton", None) for arch in _ARCHS if arch in TRITON_ARCHS
)

SCENARIO_INFO = ScenarioInfo(
    prefix="syscall",
    scenario="syscall",
    tags=("scenario", "syscall"),
    variants_source=from_variants(_VARIANTS),
    run_factory=script_assert_outputs(
        (
            ((), "Executing syscall"),
            ((), "Executing a write syscall"),
        ),
        script_template="syscall/syscall.{variant}.py",
    ),
)
