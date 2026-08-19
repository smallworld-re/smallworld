from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_assert_contains

NATIVE_PARITY = True

# Triton's CPU models cover integer and control flow only: it reports x87/SSE
# and AArch64 FP instructions as undefined, and Triton's ARM32 target does not
# expose the VFP registers at all. The variants are listed so the gap is
# visible; drop the reason if Triton ever grows floating-point semantics.
_TRITON_NO_FLOAT = "Triton implements no floating-point instruction semantics"

_VARIANTS = (
    ("aarch64", None),
    ("aarch64.angr", None),
    ("aarch64.pcode", None),
    ("aarch64.triton", _TRITON_NO_FLOAT),
    ("amd64", None),
    ("amd64.angr", None),
    ("amd64.pcode", None),
    ("amd64.triton", _TRITON_NO_FLOAT),
    ("armhf.angr", None),
    ("armhf.pcode", None),
    ("armhf.triton", _TRITON_NO_FLOAT),
    ("i386", None),
    ("i386.angr", None),
    ("i386.pcode", None),
    ("i386.triton", _TRITON_NO_FLOAT),
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
