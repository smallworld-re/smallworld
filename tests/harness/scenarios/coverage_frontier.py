from __future__ import annotations

from typing import Any, Mapping

from .spec import ScenarioInfo, from_variants, script_assert_lines

NATIVE_PARITY = True

_EXPECTATIONS = {
    "test_coverage_frontier_1": (
        "EXPECTED  One hint returned, as expected",
        "EXPECTED  One item in coverage frontier, as expected",
        "EXPECTED  Coverage frontier is as expected: 0x1158",
        "EXPECTED  No unexpected results",
    ),
    "test_coverage_frontier_2": (
        "EXPECTED  One hint returned, as expected",
        "EXPECTED  Zero items in coverage frontier, as expected",
        "EXPECTED  No unexpected results",
    ),
}

_VARIANTS = tuple((name, None) for name in _EXPECTATIONS)


def _expectations(variant: str, kwargs: Mapping[str, Any]) -> tuple[str, ...]:
    return _EXPECTATIONS[variant]


SCENARIO_INFO = ScenarioInfo(
    prefix="coverage_frontier",
    scenario="coverage_frontier",
    tags=("analysis", "coverage_frontier"),
    variants_source=from_variants(_VARIANTS),
    run_factory=script_assert_lines(
        _expectations,
        script_template="coverage_frontier/{variant}.py",
    ),
)
