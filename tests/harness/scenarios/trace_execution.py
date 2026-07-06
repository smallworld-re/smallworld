from __future__ import annotations

from typing import Any, Mapping

from .spec import ScenarioInfo, from_variants, script_assert_lines

NATIVE_PARITY = True

_EXPECTATIONS = {
    "test_trace_is_correct_1": (
        "EXPECTED  trace digest matchest truth",
        "trace is 18 instructions which is correct",
        "execption args are what we expect",
        "exception type is correct -- EmulationReadUnmappedFailure",
        "exception operands are correct -- [(x86BSIDMemoryReferenceOperand([rax]), 0)]",
        "EXPECTED  No unexpected results",
    ),
    "test_trace_is_correct_2": (
        "EXPECTED  trace digest matchest truth",
        "trace is 100 instructions which is correct",
        "no exception in trace as expected",
        "EXPECTED  No unexpected results",
    ),
    "test_trace_reproduces": (
        "EXPECTED  trace digests are same",
        "EXPECTED  traces are same number of instructions",
        "EXPECTED  No unexpected results",
    ),
    "test_traces_different": (
        "EXPECTED  trace digests are not same which is as desired",
        "EXPECTED  No unexpected results",
    ),
    "test_branch_and_cmp_info": (
        "EXPECTED  One hint returned, as expected",
        "EXPECTED  num branches is 9, as expected",
        "EXPECTED  comparisons in trace are correct",
        "EXPECTED  immediates in trace are correct",
        "EXPECTED  No unexpected results",
    ),
}

_VARIANTS = tuple((name, None) for name in _EXPECTATIONS)


def _expectations(variant: str, kwargs: Mapping[str, Any]) -> tuple[str, ...]:
    return _EXPECTATIONS[variant]


SCENARIO_INFO = ScenarioInfo(
    prefix="trace_execution",
    scenario="trace_execution",
    tags=("analysis", "trace_execution"),
    variants_source=from_variants(_VARIANTS),
    run_factory=script_assert_lines(
        _expectations,
        script_template="trace_executor/{variant}.py",
    ),
    weight=2,
)
