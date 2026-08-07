from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_assert_lines

NATIVE_PARITY = True

SCENARIO_INFO = ScenarioInfo(
    prefix="loop_detection",
    scenario="loop_detection",
    tags=("analysis", "loop_detector"),
    variants_source=from_variants((("test_loop_detector_1", None),)),
    run_factory=script_assert_lines(
        (
            "EXPECTED  found loop hint in hints1",
            "EXPECTED  found loop hint in hints2",
            "EXPECTED  loop hint in hints1 is correct",
            "EXPECTED  loop hint in hints2 is correct",
            "EXPECTED  No unexpected results",
        ),
        script_template="loop_detector/{variant}.py",
    ),
)
