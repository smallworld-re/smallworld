"""SH-2A's 32-bit memory forms and its bit-manipulation-on-memory set.

``sh2a_isa`` covers the SH-2A arithmetic and register-only additions.  This
scenario covers the ones that touch memory, which is most of the twenty-four
32-bit encodings - the only 32-bit instructions in the SuperH family - plus all
ten ``*.b #imm3,@(disp12,Rn)`` bit operations, which nothing else exercises.

Two properties are checked deliberately because they are the easy ones to get
wrong:

* **Extension.** ``movu.w`` zero-extends where ``mov.w`` sign-extends.  The blob
  stores ``0x8000`` and reads it back both ways, so a backend that implements
  ``movu.w`` as a sign-extending load is caught (``r5`` would be ``0xffff8000``).
* **Displacement scaling**, which differs per width: unscaled for ``.b``, by 2
  for ``.w``, by 4 for ``.l``.  Each store/load pair uses the same displacement,
  so a mis-scaled implementation reads back the wrong bytes.

``r9`` and ``r13`` are asserted as absolute addresses, which ties this scenario to
the stack geometry in the spec below (base 0x2000, size 0x4000, so the incoming
stack pointer is 0x6000).  That is intentional: it makes the pointer arithmetic
itself part of the cross-backend comparison rather than something each backend
gets to disagree about silently.
"""

from __future__ import annotations

from typing import Dict, Sequence

from .common import PlatformSpec, split_variant
from .sh2a_fpu import FPSCR_SINGLE, RegisterCaseSpec, run_register_case
from .spec import ScenarioInfo, from_arch_table, just_run

NATIVE_PARITY = True

_ARCH = "sh2a"
_SCENARIO = "sh2a_isa_mem"

# Integer-only, so angr's missing floating-point support is irrelevant here.
_ENGINES = ("angr", "pcode", "styx", "panda")


# angr stores zero for any 16-bit memory write.  Isolated to the store side, and
# not to SuperH: with memory pre-seeded to 0x1234abcd, `mov.w @r5,r1` loads 0x1234
# correctly and `mov.l @r5,r2` loads 0x1234abcd correctly, but running
# `mov.w r1,@r5` with r1 = 0x1234 over memory pre-filled with 0xee leaves
# `0000eeee` instead of `1234eeee`.  Ghidra returns `1234eeee`.  The plain SH-2
# `mov.w Rm,@Rn` form fails identically to SH-2A's 32-bit displaced form, so this
# is not an SH-2A decode issue; and the two bundled `superh.sinc` copies differ
# only in the `bclr` rule, so it is not the sleigh either.  I did not separate
# angr's pcode engine from SmallWorld's angr memory integration as the culprit.
_ANGR_HALFWORD_STORE = (
    "angr writes zero for 16-bit stores: mov.w r1,@r5 with r1=0x1234 leaves "
    "0x0000 in memory (16-bit loads and 32-bit stores are fine)"
)

_STACK_BASE = 0x2000
_STACK_SIZE = 0x4000
_SP = _STACK_BASE + _STACK_SIZE  # what Stack.get_pointer() returns
_SCRATCH = _SP - 128

SPECS: Dict[str, RegisterCaseSpec] = {
    _ARCH: RegisterCaseSpec(
        platform=PlatformSpec("SUPERH_SH2A_FPU", "BIG"),
        engines=_ENGINES,
        fpscr=FPSCR_SINGLE,
        # SR seeded so T is concrete before the bit ops read it; see the note in
        # sh2a_delayslot for why this is done from the harness and why bit 30 is
        # set rather than writing a plain zero.
        inputs={"sr": 0x40000000},
        expected={
            # Displaced halfword access.  0x1234 is positive, so both loads agree.
            "r1": 0x00001234,
            "r2": 0x00001234,  # movu.w
            "r3": 0x00001234,  # mov.w
            # 0x8000 has its top bit set, so here the two loads must differ.
            "r4": 0x00008000,
            "r5": 0x00008000,  # movu.w, zero-extended
            "r6": 0xFFFF8000,  # mov.w,  sign-extended
            # Displaced longword access.
            "r7": 0x0005A5A5,
            "r8": 0x0005A5A5,
            # mov.b R0,@Rn+ then mov.b @-Rm,R0: the pointer returns to where it
            # started and the byte round-trips.
            "r0": 0x0000007B,
            "r9": _SCRATCH + 32,
            "r13": _SCRATCH,
            # T sampled at three points through the ten bit operations.
            "r10": 1,
            "r11": 0,
            "r12": 1,
            # The byte the ten operations left behind.
            "r14": 0x11,
        },
        stack_base=_STACK_BASE,
        stack_size=_STACK_SIZE,
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
            f"{_ARCH}.angr": _ANGR_HALFWORD_STORE,
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
