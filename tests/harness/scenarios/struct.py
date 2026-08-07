from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_assert_contains

NATIVE_PARITY = True

_VARIANTS = (
    ("amd64", None),
    ("amd64.panda", None),
)

SCENARIO_INFO = ScenarioInfo(
    prefix="struct",
    scenario="struct",
    tags=("scenario", "struct"),
    variants_source=from_variants(_VARIANTS),
    run_factory=script_assert_contains(
        "node_b->data = 42",
        script_template="struct/struct.{variant}.py",
    ),
)
