"""SH-2A ``MOVML.L``/``MOVMU.L`` with ``Rm = R15``, where slot 15 holds PR.

A regression test for a bug that code review caught and no test would have.
Transfer index 15 names **PR**, not R15, in both instructions and both
directions - so R15 is never itself an operand::

    MOVML.L Rm,@-R15   saves R0..Rm             (PR when m == 15)
    MOVMU.L Rm,@-R15   saves Rm..R14 and PR     (PR alone when m == 15)

An earlier revision of ``nix/patches/panda-qemu-sh2a.patch`` substituted PR only
in MOVMU's last slot, leaving MOVML to push the stack pointer where the return
address belonged and never restore PR.  ``gcc -m2a`` emits the MOVMU form in
essentially every prologue and epilogue, so getting this wrong breaks all
compiled SH-2A code while leaving hand-written test assembly working.

The blob checks three cases so a passing result cannot come from the substitution
being applied indiscriminately:

* ``movml.l r15`` - PR is saved and restored, so the sentinel survives a clobber.
* ``movmu.l r15`` - PR alone, a single-word push, easy to implement as zero or
  sixteen words instead.
* ``movml.l r13`` - the adjacent non-PR case, where PR must come back *clobbered*
  because it was never part of the transfer.
"""

from __future__ import annotations

from typing import Dict, Sequence

from .common import PlatformSpec, split_variant
from .sh2a_fpu import FPSCR_SINGLE, RegisterCaseSpec, run_register_case
from .spec import ScenarioInfo, from_arch_table, just_run

NATIVE_PARITY = True

_ARCH = "sh2a"
_SCENARIO = "sh2a_movml"

_ENGINES = ("angr", "pcode", "styx", "panda")

SPECS: Dict[str, RegisterCaseSpec] = {
    _ARCH: RegisterCaseSpec(
        platform=PlatformSpec("SUPERH_SH2A_FPU", "BIG"),
        engines=_ENGINES,
        fpscr=FPSCR_SINGLE,
        # SR seeded from the harness so MD is set and T is concrete; see
        # sh2a_delayslot for why this does not come from an in-blob `ldc`.
        inputs={"sr": 0x40000000},
        expected={
            # movml.l r15: PR saved in slot 15 and restored over the clobber.
            "r0": 0x55,
            # movmu.l r15: PR alone.
            "r3": 0x66,
            # movml.l r13: PR never saved, so the clobber survives.
            "r5": 0x78,
        },
    )
}

SCENARIO_PREFIXES = ((_SCENARIO, _SCENARIO),)

SCENARIO_INFO = ScenarioInfo(
    prefix=_SCENARIO,
    scenario=_SCENARIO,
    tags=("scenario", _SCENARIO, "sh2a"),
    variants_source=from_arch_table(SPECS),
    run_factory=just_run(),
)


def can_run(scenario: str, variant: str) -> bool:
    if scenario != _SCENARIO:
        return False
    arch, engine = split_variant(variant)
    return arch in SPECS and engine in SPECS[arch].engines


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    arch, _ = split_variant(variant)
    return run_register_case(scenario, variant, SPECS[arch])
