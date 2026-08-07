from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_assert_contains

NATIVE_PARITY = True

_VARIANTS = (
    ("test_colorizer_1", None),
    ("test_colorizer_2", None),
)

SCENARIO_INFO = ScenarioInfo(
    prefix="colorizer",
    scenario="colorizer",
    tags=("analysis", "colorizer"),
    variants_source=from_variants(_VARIANTS),
    run_factory=script_assert_contains(
        "EXPECTED  No unexpected results",
        script_template="colorizer/{variant}.py",
    ),
)
