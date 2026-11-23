from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_just_run

NATIVE_PARITY = True

_VARIANTS = (
    ("aarch64", None),
    ("aarch64v85a", None),
    ("aarch64be", None),
    ("aarch64v85abe", None),
    ("amd64", None),
    ("armv6k", None),
    ("armv6kbe", None),
    ("armv5t", None),
    ("armv5tbe", None),
    ("armv4t", None),
    ("armv4tbe", None),
    ("armv6m", None),
    ("armv7m", None),
    ("armv7em", None),
    ("armv8m", None),
    ("armv7a.pcode", None),
    ("armv7abe.pcode", None),
    ("armv7r.pcode", None),
    ("armv7rbe.pcode", None),
    ("armv8a.pcode", None),
    ("armv8abe.pcode", None),
    ("armv8r.pcode", None),
    ("armv8rbe.pcode", None),
    ("i386", None),
    ("la64.pcode", None),
    ("mips.pcode", None),
    ("mips64.pcode", None),
    ("mips64el.pcode", None),
    ("mipsel.pcode", None),
    ("ppc.pcode", None),
    ("ppc64", None),
    ("ppc64.pcode", None),
    ("riscv32.pcode", None),
    ("riscv64.pcode", None),
)

SCENARIO_INFO = ScenarioInfo(
    prefix="funcptr",
    scenario="funcptr",
    tags=("scenario", "funcptr"),
    variants_source=from_variants(_VARIANTS),
    run_factory=script_just_run(script_template="funcptr/funcptr.{variant}.py"),
)
