"""SH-2A register-form bit manipulation, and the ``bclr #imm3,Rn`` sleigh bug.

Split out of ``sh2a_diff`` so that one broken instruction does not remove two of
four backends from a comparison whose purpose is to span them.

**The bug.** Ghidra 12.1.2's ``superh.sinc`` implements the register form as::

    rn_04_07 = rn_04_07 & (~(1 << imm3_00_02));

while pypcode 3.3.3 and Styx bundle an older revision of the same rule::

    local b = *:1 (rn_04_07);
    *:1 (rn_04_07) = b & (~(1 << imm3_00_02));

That treats ``Rn`` as a *pointer* - clearing a bit in the byte at that address and
leaving the register alone - which is the ``bclr.b @(disp,Rn)`` memory semantics
wrongly applied to the register form.  Diffing the two files shows it is their
only difference, so it was fixed upstream somewhere between the revision pypcode
vendors and Ghidra 12.1.2.

It is worse than a crash.  On both affected backends the spurious access
*succeeds* - angr's memory is lazily symbolic, and Styx maps a flat 4 GiB - so the
instruction silently corrupts memory at ``Rn``'s value and returns an unmodified
register instead of faulting.

Found by the ``sh2a_diff`` cross-backend comparison: ``bclr #5`` applied to 0x22
left 0x22 on angr and Styx but correctly gave 0x02 on Ghidra.  Nothing that
checks one engine at a time would have noticed, because the two wrong backends
agree with each other.

Ghidra 12.1.2 is right: clearing bit 5 of 0x22 gives 0x02.  ``bset``, ``bld`` and
``bst`` are correct everywhere and are covered here too, so the scenario still
earns its place once the skips are lifted.
"""

from __future__ import annotations

from typing import Dict, Sequence

from .common import PlatformSpec, split_variant
from .sh2a_fpu import FPSCR_SINGLE, RegisterCaseSpec, run_register_case
from .spec import ScenarioInfo, from_arch_table, just_run

NATIVE_PARITY = True

_ARCH = "sh2a"
_SCENARIO = "sh2a_bitreg"

_ENGINES = ("angr", "pcode", "styx", "panda")

_BCLR_BROKEN = (
    "bclr #imm3,Rn is broken in the superh.sinc that pypcode 3.3.3 and Styx "
    "bundle: it clears a bit in memory at Rn instead of in the register "
    "(fixed in Ghidra 12.1.2)"
)

SPECS: Dict[str, RegisterCaseSpec] = {
    _ARCH: RegisterCaseSpec(
        platform=PlatformSpec("SUPERH_SH2A_FPU", "BIG"),
        engines=_ENGINES,
        fpscr=FPSCR_SINGLE,
        # SR seeded so T is concrete before bld/bst/movt touch it; see
        # sh2a_delayslot for why this comes from the harness rather than an `ldc`.
        inputs={"sr": 0x40000000},
        expected={
            "r1": 0x00000002,  # bset #5, bset #1, bclr #5
            "r2": 1,  # bld #1 -> T, then movt
            "r3": 0x00000000,  # bst #7 with T=1, nott, bst #7 with T=0
            "r4": 0,  # movt after nott
        },
    )
}

SCENARIO_PREFIXES = ((_SCENARIO, _SCENARIO),)

SCENARIO_INFO = ScenarioInfo(
    prefix=_SCENARIO,
    scenario=_SCENARIO,
    tags=("scenario", _SCENARIO, "sh2a"),
    variants_source=from_arch_table(
        SPECS,
        skip_reasons={
            f"{_ARCH}.angr": _BCLR_BROKEN,
            f"{_ARCH}.styx": _BCLR_BROKEN,
        },
    ),
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
