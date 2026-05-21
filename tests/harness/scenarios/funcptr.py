from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_just_run

NATIVE_PARITY = True

_VARIANTS = (
    ("aarch64", None),
    ("amd64", None),
    ("armel", None),
    ("armhf.pcode", None),
    ("i386", None),
    ("la64.pcode", None),
    ("mips.pcode", None),
    ("mips64.pcode", None),
    ("mips64el.pcode", None),
    ("mipsel.pcode", None),
    ("ppc.pcode", None),
    ("riscv64.pcode", None),
)

SCENARIO_INFO = ScenarioInfo(
    prefix="funcptr",
    scenario="funcptr",
    tags=("scenario", "funcptr"),
    variants_source=from_variants(_VARIANTS),
    run_factory=script_just_run(script_template="funcptr/funcptr.{variant}.py"),
)
