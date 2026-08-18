from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_assert_outputs

NATIVE_PARITY = True

_VARIANTS = tuple(
    (f"{arch}.angr", None)
    for arch in (
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
        # same arrangement for the same reason.  angr is the only engine here
        # because it is the only backend that implements hook_syscall at all -
        # on PANDA the very same instruction is an interrupt instead, which is
        # what the `interrupt` scenario covers.
        "sh2a",
        "sh4",
        "sh4el",
        "xtensa",
    )
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
