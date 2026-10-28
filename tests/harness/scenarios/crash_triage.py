from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_just_run

NATIVE_PARITY = True

_VARIANTS = tuple(
    (arch, None)
    for arch in (
        "aarch64",
        "aarch64be",
        "amd64",
        "armv6k",
        "armv6kbe",
        "armv5t",
        "armv5tbe",
        "armv4t",
        "armv4tbe",
        "armv7m",
        "armv7em",
        "armv6m",
        "armv8m",
        "armv7a",
        "armv7abe",
        "armv7r",
        "armv7rbe",
        "armv8a",
        "armv8abe",
        "armv8r",
        "armv8rbe",
        "i386",
        "mips",
        "mipsel",
    )
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
