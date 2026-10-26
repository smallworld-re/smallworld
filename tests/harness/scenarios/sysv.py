from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_just_run

NATIVE_PARITY = True

_VARIANTS = tuple(
    (arch, None)
    for arch in (
        "aarch64",
        "amd64",
        "armv6k",
        "armv7a",
        "armv7r",
        "armv8a",
        "armv8r",
        "armv8m",
        "i386",
        "la64",
        "m68k",
        "mips",
        "mipsel",
        "mips64",
        "mips64el",
        "ppc",
        "riscv64",
    )
)

SCENARIO_INFO = ScenarioInfo(
    prefix="sysv",
    scenario="sysv",
    tags=("scenario", "sysv"),
    variants_source=from_variants(_VARIANTS),
    run_factory=script_just_run(script_template="sysv/sysv.{variant}.py"),
)
