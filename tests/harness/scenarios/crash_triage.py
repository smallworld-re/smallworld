from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_just_run

NATIVE_PARITY = True

_VARIANTS = tuple(
    (arch, None)
    for arch in ("aarch64", "amd64", "armel", "armhf", "i386", "mips", "mipsel")
)

SCENARIO_INFO = ScenarioInfo(
    prefix="crash_triage",
    scenario="crash_triage",
    tags=("analysis", "crash_triage"),
    variants_source=from_variants(_VARIANTS),
    run_factory=script_just_run(
        script_template="crash_triage/crash_triage.{variant}.py",
    ),
    weight=2,
)
