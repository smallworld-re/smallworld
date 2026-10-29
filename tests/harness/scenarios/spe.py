from __future__ import annotations

from typing import Sequence

from .common import build_specs
from .raw_binary import RawBinarySpec, run_integer_case, supports_variant
from .spec import ScenarioInfo, assert_outputs, from_arch_table

NATIVE_PARITY = True

# PowerPC SPE embedded floating point, as the e200 runs it instead of a
# classic FPU. Only the VLE platform has an SPE test; the single-precision
# instructions are the same on any e200.
_ARCHS = ("ppcvle",)

_SPECS = build_specs(RawBinarySpec, _ARCHS)

# Blocked upstream, as in the floats scenario: angr's pcode engine
# implements none of the OpBehaviorFloat* operations
# (angr/engines/pcode/behavior.py), so floating point fails on every
# pcode-backed architecture. Measured: efscfsi raises AngrError("Not
# implemented!") on its int2float. The binary and expected outputs are
# correct; drop the skip when angr implements the behaviors.
_SKIP_REASONS = {
    "ppcvle.angr": (
        "angr's pcode engine implements no floating-point arithmetic: every "
        "OpBehaviorFloat* in angr/engines/pcode/behavior.py is unimplemented "
        "(upstream, affects every pcode-backed arch)"
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
