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
    # SuperH selects precision from FPSCR rather than the opcode, so these run
    # single-precision with PR=0; 2.2 + 1.1 comes out as 3.3000002, which still
    # carries the "3.3" this scenario asserts on.  Double precision is broken on
    # Styx for SuperH, so it stays out of reach here.
    #
    # The angr variants are blocked upstream rather than by anything SuperH
    # specific: every OpBehaviorFloat* class in angr's pcode engine
    # (angr/engines/pcode/behavior.py) still has its evaluate_binary body
    # commented out as unported C++, so the base class raises
    # AngrError("Not implemented!").  That makes floating-point arithmetic
    # unavailable for *any* pcode-backed architecture in angr, not just SuperH.
    # The runner scripts are written and correct; drop the skip when angr
    # implements the behaviors.
    ("sh2a.pcode", None),
    (
        "sh2a.angr",
        (
            "angr's pcode engine implements no floating-point arithmetic: every OpBehaviorFloat* in angr/engines/pcode/behavior.py is unimplemented (upstream, affects every pcode-backed arch)"
        ),
    ),
    ("sh2a.styx", None),
    ("sh4.pcode", None),
    (
        "sh4.angr",
        (
            "angr's pcode engine implements no floating-point arithmetic: every OpBehaviorFloat* in angr/engines/pcode/behavior.py is unimplemented (upstream, affects every pcode-backed arch)"
        ),
    ),
    ("sh4el.pcode", None),
    (
        "sh4el.angr",
        (
            "angr's pcode engine implements no floating-point arithmetic: every OpBehaviorFloat* in angr/engines/pcode/behavior.py is unimplemented (upstream, affects every pcode-backed arch)"
        ),
    ),
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
