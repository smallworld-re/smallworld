from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_just_run

NATIVE_PARITY = True

# Calls between standard MIPS32 and microMIPS code. Only Ghidra switches
# between the two; the other backends run MIPS32_MICROMIPS as microMIPS only.
_MICROMIPS_ONLY = {
    "angr": "angr's p-code engine decodes only microMIPS on this platform",
    "unicorn": "SmallWorld cannot read Unicorn's ISA mode, so it runs only microMIPS",
}

_VARIANTS = tuple(
    (variant, reason)
    for arch in ("micromips", "micromipsel")
    for variant, reason in (
        (f"{arch}.pcode", None),
        (f"{arch}.angr", _MICROMIPS_ONLY["angr"]),
        (arch, _MICROMIPS_ONLY["unicorn"]),
    )
)

SCENARIO_INFO = ScenarioInfo(
    prefix="interwork",
    scenario="interwork",
    tags=("scenario", "interwork"),
    variants_source=from_variants(_VARIANTS),
    run_factory=script_just_run(script_template="interwork/interwork.{variant}.py"),
)
