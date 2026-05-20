from __future__ import annotations

from typing import Sequence

from .common import build_specs
from .raw_binary import RawBinarySpec, run_integer_case, supports_variant
from .spec import ScenarioInfo, assert_outputs, from_legacy

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
    common={"print_mode": "register"},
    # branch prints the 32-bit view on aarch64 so the boolean fits.
    per_arch={"aarch64": {"result_register": "w0"}},
)

SCENARIO_PREFIXES = (("branch", "branch"),)

SCENARIO_INFO = ScenarioInfo(
    prefix="branch",
    scenario="branch",
    tags=("scenario", "branch"),
    variants_source=from_legacy(
        (
            "BranchTestsAngr",
            "BranchTestsGhidra",
            "BranchTestsPanda",
            "BranchTestsUnicorn",
        ),
        prefix="branch",
    ),
    run_factory=assert_outputs(
        (
            (("99",), "0x0"),
            (("100",), "0x1"),
            (("101",), "0x0"),
        ),
    ),
)


def can_run(scenario: str, variant: str) -> bool:
    return scenario == "branch" and supports_variant(variant, _SPECS)


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    return run_integer_case("branch", variant, args, _SPECS)
