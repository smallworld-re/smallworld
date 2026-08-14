from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_assert_contains

NATIVE_PARITY = True

_VARIANTS = (
    ("aarch64", None),
    ("aarch64.angr", None),
    ("aarch64.pcode", None),
    ("amd64", None),
    ("amd64.angr", None),
    ("amd64.pcode", None),
    ("armhf.angr", None),
    ("armhf.pcode", None),
    ("i386", None),
    ("i386.angr", None),
    ("i386.pcode", None),
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
    ("sh2a.angr", "angr's pcode engine has no float behaviors implemented"),
    ("sh2a.styx", None),
    ("sh4.pcode", None),
    ("sh4.angr", "angr's pcode engine has no float behaviors implemented"),
    ("sh4el.pcode", None),
    ("sh4el.angr", "angr's pcode engine has no float behaviors implemented"),
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
