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
