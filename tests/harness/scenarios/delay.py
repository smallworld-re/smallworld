from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_just_run

NATIVE_PARITY = True

_VARIANTS = tuple(
    (variant, None)
    for arch in ("mips", "mipsel", "mips64", "mips64el")
    for variant in (arch, f"{arch}.angr", f"{arch}.panda", f"{arch}.pcode")
)

SCENARIO_INFO = ScenarioInfo(
    prefix="delay",
    scenario="delay",
    tags=("scenario", "delay"),
    variants_source=from_variants(_VARIANTS),
    run_factory=script_just_run(script_template="delay/delay.{variant}.py"),
)
