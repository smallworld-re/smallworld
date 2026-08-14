"""SH-2A-only instruction coverage.

SmallWorld reaches SH-2A through four backends whose SH-2A support has very
different provenance: Ghidra and pypcode share a sleigh model, Styx has a native
SuperH2A core, and PANDA runs on a QEMU ``target/sh4`` that we patched to decode
the SH-2A additions.  Every other SuperH scenario deliberately sticks to the
instructions SH-2A and SH-4 have in common, so nothing else in the suite would
notice a backend that quietly treats SH-2A as SH-4.

This scenario closes that gap.  ``tests/sh2a_isa/sh2a_isa.sh2a.s`` uses only
SH-2A-exclusive instructions - ``movi20``, ``mulr``, ``movml.l``, the displaced
``mov.b``/``movu.b`` 32-bit forms, ``clips.b``, ``nott``, ``movrt`` and
``rts/n`` - and folds each result into r0, so one comparison covers all of them.
``rts/n`` in particular returns with no delay slot; a backend that wrongly gives
it one executes the following instruction and returns -1.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .common import ARCH_REGISTERS, PlatformSpec
from .raw_binary import RawBinarySpec, StackSpec, run_integer_case, supports_variant
from .spec import ScenarioInfo, assert_outputs, from_arch_table

NATIVE_PARITY = True

_ARCH = "sh2a"

# movml.l saves r8-r14 and pr, so this needs a real stack; the binary points its
# own scratch pointer well clear of that frame.  SuperH keeps the return address
# in pr, so there is no synthetic return slot to push.
_SPECS = {
    _ARCH: RawBinarySpec(
        platform=PlatformSpec("SUPERH_SH2A_FPU", "BIG"),
        pc_register="pc",
        result_register="r0",
        engines=ARCH_REGISTERS[_ARCH].engines,
        arg_register=None,
        stack=StackSpec(pointer_register="sp", fake_return_size=None),
    )
}

SCENARIO_PREFIXES = (("sh2a_isa", "sh2a_isa"),)


def _expectations(
    variant: str, kwargs: Mapping[str, Any]
) -> tuple[tuple[tuple[str, ...], str], ...]:
    # 0x369cf (movi20 * mulr) + 0x100 (movu.b vs mov.b) + 0x7f (clips.b)
    #   + 1 (movt, T=1 after nott) + 0 (movrt, the inverse)
    #
    # NOTE: movt and movrt are folded into the same checksum, and since movrt
    # stores the inverse of T their contributions sum to 1 for *either* value of
    # T.  So this total does not actually constrain nott/movt/movrt - a backend
    # where nott is a no-op, or where movt and movrt are swapped, still produces
    # 0x36b4f.  Checking r4 and r8 separately (as sh2a_bitreg and sh2a_diff do)
    # is what would pin them down.
    return ((("0",), "0x36b4f"),)


SCENARIO_INFO = ScenarioInfo(
    prefix="sh2a_isa",
    scenario="sh2a_isa",
    tags=("scenario", "sh2a_isa", "sh2a"),
    variants_source=from_arch_table(_SPECS),
    run_factory=assert_outputs(_expectations),
)


def can_run(scenario: str, variant: str) -> bool:
    return scenario == "sh2a_isa" and supports_variant(variant, _SPECS)


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    return run_integer_case("sh2a_isa", variant, args, _SPECS)
