from __future__ import annotations

from typing import Sequence

from .common import build_specs
from .raw_binary import RawBinarySpec, run_integer_case, supports_variant
from .spec import ScenarioInfo, assert_outputs, from_arch_table

NATIVE_PARITY = True

# PowerPC SPE embedded floating point, which e200 cores with floating point
# have instead of a classic FPU (the e200z0 has none). Only the VLE platform
# has an SPE test; the single-precision instructions are the same on any
# e200 that has them.
_ARCHS = ("ppcvle",)

_SPECS = build_specs(RawBinarySpec, _ARCHS)

# Blocked upstream: Sleigh lifts efscfsi and efsctsiz with branches inside
# their own p-code (const-space CBRANCH/BRANCH), which angr's engine cannot
# take: it fails on "FIXME: Test statement_offset behavior". That needs an
# angr fix. (The other blocker, angr's missing floating-point operations, is
# gone: SmallWorld supplies them.) The binary and expected outputs are
# correct.
_SKIP_REASONS = {
    "ppcvle.angr": (
        "angr's pcode engine cannot take the branches inside efscfsi's and "
        "efsctsiz's p-code (an upstream angr limitation)"
    ),
}

SCENARIO_PREFIXES = (("spe", "spe"),)


def _trunc_half_square_minus_ten(n: int) -> int:
    # Truncate toward zero, as efsctsiz does, and return the 32-bit pattern.
    numerator = n * n - 20
    result = abs(numerator) // 2 * (1 if numerator >= 0 else -1)
    return result & 0xFFFFFFFF


SCENARIO_INFO = ScenarioInfo(
    prefix="spe",
    scenario="spe",
    tags=("scenario", "spe"),
    variants_source=from_arch_table(_SPECS, skip_reasons=_SKIP_REASONS),
    run_factory=assert_outputs(
        tuple(
            ((str(n),), f"{_trunc_half_square_minus_ten(n):#x}")
            for n in (5, 7, 3, -3, 0)
        )
    ),
)


def can_run(scenario: str, variant: str) -> bool:
    return scenario == "spe" and supports_variant(variant, _SPECS)


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if variant in _SKIP_REASONS:
        raise SystemExit(_SKIP_REASONS[variant])
    return run_integer_case("spe", variant, args, _SPECS)
