from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_assert_contains

NATIVE_PARITY = True

_VARIANTS = (
    ("aarch64", None),
    ("aarch64.angr", None),
    ("aarch64.pcode", None),
    ("amd64", None),
    ("amd64.angr", None),
    ("amd64.pcode", None),
    ("armhf.angr", None),
    ("armhf.pcode", None),
    ("i386", None),
    ("i386.angr", None),
    ("i386.pcode", None),
)

SCENARIO_INFO = ScenarioInfo(
    prefix="floats",
    scenario="floats",
    tags=("scenario", "floats"),
    variants_source=from_variants(_VARIANTS),
    run_factory=script_assert_contains(
        "3.3",
        script_template="floats/floats.{variant}.py",
        args=("2.2", "1.1"),
    ),
)
