from __future__ import annotations

import dataclasses
from typing import Any, Mapping, Sequence

from .common import build_specs
from .raw_binary import RawBinarySpec, run_integer_case, supports_variant
from .spec import ScenarioInfo, assert_outputs, from_arch_table

NATIVE_PARITY = True

_ARCHS = (
    "aarch64",
    "amd64",
    "armel",
    "armhf",
    "i386",
    "la64",
    "m68k",
    "mips",
    "mipsel",
    "mips64",
    "mips64el",
    "msp430",
    "msp430x",
    "ppc",
    "ppc64",
    "riscv64",
    "tricore",
    "xtensa",
)

_SPECS = build_specs(
    RawBinarySpec,
    _ARCHS,
    # la64's mul.w writes a0; the binary reads v0, which aliases the same reg.
    per_arch={"la64": {"result_register": "v0"}},
)

_SPECIAL_VARIANTS = {
    "ppc.panda": dataclasses.replace(
        _SPECS["ppc"],
        engines=("panda",),
        print_exit_point=True,
    ),
}

SCENARIO_PREFIXES = (("square", "square"),)


def _square_expectations(
    variant: str, kwargs: Mapping[str, Any]
) -> tuple[tuple[tuple[str, ...], str], ...]:
    signext = bool(kwargs.get("signext", False))
    sixteenbit = bool(kwargs.get("sixteenbit", False))
    numbers = [5, 1337]
    if not sixteenbit:
        numbers.append(65535)
    expectations: list[tuple[tuple[str, ...], str]] = []
    for number in numbers:
        result = number**2
        if signext and result & 0xFFFFFFFF80000000 != 0:
            result = 0xFFFFFFFF80000000 | result
        if sixteenbit:
            result &= 0xFFFF
        expectations.append(((str(number),), f"{result:#x}"))
    return tuple(expectations)


SCENARIO_INFO = ScenarioInfo(
    prefix="square",
    scenario="square",
    tags=("scenario", "square"),
    variants_source=from_arch_table(
        _SPECS,
        skip_reasons={"ppc64": "Unicorn ppc64 support buggy"},
        arch_kwargs={
            **{
                arch: {"signext": True}
                for arch in ("mips64", "mips64el", "ppc64", "riscv64")
            },
            **{arch: {"sixteenbit": True} for arch in ("msp430", "msp430x")},
        },
    ),
    run_factory=assert_outputs(_square_expectations),
)


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "square":
        return False
    if variant in _SPECIAL_VARIANTS:
        return True
    return supports_variant(variant, _SPECS)


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if variant in _SPECIAL_VARIANTS:
        return run_integer_case(
            "square", variant, args, {"ppc": _SPECIAL_VARIANTS[variant]}
        )
    return run_integer_case("square", variant, args, _SPECS)
