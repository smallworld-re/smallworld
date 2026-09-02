"""Conditional delayed branches on SH-2A: ``bt/s`` and ``bf/s``.

Both are in the platform definition's ``delay_slot_mnemonics`` and had no coverage
anywhere in the suite before this scenario.  They deserve it because the Renesas
pseudocode reads as though the delay slot is skipped when the branch is not taken,
whereas both implementations available to us execute it unconditionally and make
only the *branch* conditional:

* QEMU's ``target/sh4/translate.c`` latches the condition into
  ``cpu_delayed_cond``, sets ``TB_FLAG_DELAY_SLOT_COND`` and returns - so the
  delay slot is decoded and executed like any other instruction - and
  ``gen_delayed_conditional_jump`` resolves the branch afterwards.
* Ghidra's ``superh.sinc`` does ``local cond = T; delayslot(1); if (cond) goto``.

Two independent implementations agreeing settles the semantics, and the blob pins
down the consequence that follows from *latching*: a delay-slot instruction may
modify the branch condition's source - up to and including ``T`` itself - without
changing whether the branch is taken.

The blob is integer-only and input-free, so it is directly comparable across
backends.  It reuses the register-comparison runner from :mod:`sh2a_fpu`.
"""

from __future__ import annotations

from typing import Dict, Sequence

from .common import PlatformSpec, split_variant
from .sh2a_fpu import FPSCR_SINGLE, RegisterCaseSpec, run_register_case
from .spec import ScenarioInfo, from_arch_table, just_run

NATIVE_PARITY = True

_ARCH = "sh2a"
_SCENARIO = "sh2a_delayslot"

# angr is included: this blob is integer-only, so the engine's missing
# floating-point support is irrelevant here.
_ENGINES = ("angr", "pcode", "styx", "panda")


SPECS: Dict[str, RegisterCaseSpec] = {
    _ARCH: RegisterCaseSpec(
        platform=PlatformSpec("SUPERH_SH2A_FPU", "BIG"),
        engines=_ENGINES,
        fpscr=FPSCR_SINGLE,
        # Seed SR so the T bit is concrete before anything reads it.  SH-2A has no
        # standalone T register - it is the bitfield sr[0,1] - so on a symbolic
        # backend an unconstrained SR propagates into every `movt` result: angr
        # otherwise returns r4 as a bitvector that *reduces* to 0 but is never
        # simplified, because SR's other bits stay symbolic.
        #
        # Seeded from the harness rather than with a `mov #0,r1; ldc r1,sr`
        # preamble in the blob, deliberately.  `ldc Rm,SR` is privileged and
        # writing 0 to SR clears SR.MD, which would drop a full-system backend
        # into user mode; bit 30 is set here to keep QEMU privileged while leaving
        # every SH-2A-visible bit (T, S, I0-I3, Q, M, CS, BO) clear.
        inputs={"sr": 0x40000000},
        expected={
            # A: bt/s not taken.  10 would mean the delay slot was suppressed;
            # 0xffffffff + 1 would mean the branch was wrongly taken.
            "r1": 11,
            # B: bf/s taken, with the delay slot clobbering the compare's source.
            "r0": 1,  # last written by case C's `mov #1, r0`
            "r2": 5,
            # C: bt/s taken, with the delay slot inverting T after the latch.
            # 6 here would mean the backend re-read T when resolving the branch.
            "r3": 7,
            # T still shows the delay slot's nott, proving it executed.
            "r4": 0,
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
