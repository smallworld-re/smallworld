from __future__ import annotations

import argparse
import logging
from typing import Any, Mapping, Sequence

from .common import (
    ARCH_REGISTERS,
    make_emulator,
    make_platform,
    split_variant,
)
from .spec import ScenarioInfo, assert_outputs

NATIVE_PARITY = False

# Each SuperH version must refuse the instructions of the later ones, as the
# CPU would, rather than run them as SH-2A. These are hand-assembled and
# checked against Ghidra's SH-1, SH-2 and SH-2A languages:
#
#   dt r1                 (SH-2 and later)  41 10
#   bt/s .+4              (SH-2 and later)  8d 00, delay slot add #1,r1 (71 01)
#   bra .+4               (all)             a0 00, delay slot dt r1 (41 10)
#   mul.l r1,r1           (SH-2 and later)  01 17, then sts macl,r1 (01 1a)
#   braf r2               (SH-2 and later)  mov #0,r2 (e2 00), 02 23,
#                                           delay slot add #1,r1 (71 01)
#   movi20 #0x1234,r1     (SH-2A only)      01 00 12 34
#   lds r2,fpul           (SH-2A only)      mov #5,r2 (e2 05), 42 5a,
#                                           then sts fpul,r1 (01 5a)
#
# Each is followed by a nop, and the run stops at the end of the program.  sr
# is 0, so bt/s is not taken, but its delay slot still runs.  bra itself is
# valid on SH-1, so only its delay slot is refused there.  SH-2A's shad and
# shld are left out: angr cannot run them, because their p-code branches within
# the instruction.
_PROGRAMS = {
    "dt": bytes.fromhex("4110" "0009"),
    "bts": bytes.fromhex("8d00" "7101" "0009"),
    "slot_dt": bytes.fromhex("a000" "4110" "0009"),
    "mull": bytes.fromhex("0117" "011a" "0009"),
    "braf": bytes.fromhex("e200" "0223" "7101" "0009"),
    "movi20": bytes.fromhex("0100" "1234" "0009"),
    "fpul": bytes.fromhex("e205" "425a" "015a" "0009"),
}

# The first SH version with each instruction.
_INTRODUCED = {
    "dt": "sh2",
    "bts": "sh2",
    "slot_dt": "sh2",
    "mull": "sh2",
    "braf": "sh2",
    "movi20": "sh2a",
    "fpul": "sh2a",
}
_ORDER = ("sh1", "sh2", "sh2a")

# r1 before and after each program, where the instruction runs.
_R1_IN = 0x10
_R1_OUT = {
    "dt": 0xF,
    "bts": 0x11,
    "slot_dt": 0xF,
    "mull": 0x100,
    "braf": 0x11,
    "movi20": 0x1234,
    "fpul": 0x5,
}

_ARCHS = ("sh1", "sh2", "sh2a")
_ENGINES = ("angr", "pcode")

SCENARIO_PREFIXES = (("superh_isa", "superh_isa"),)


def _expectations(
    variant: str, kwargs: Mapping[str, Any]
) -> tuple[tuple[tuple[str, ...], str], ...]:
    arch, _ = split_variant(variant)
    out = []
    for program, introduced in _INTRODUCED.items():
        if _ORDER.index(arch) >= _ORDER.index(introduced):
            out.append(((program,), f"r1={_R1_OUT[program]:#010x}"))
        else:
            out.append(((program,), "illegal instruction"))
    return tuple(out)


SCENARIO_INFO = ScenarioInfo(
    prefix="superh_isa",
    scenario="superh_isa",
    tags=("scenario", "superh_isa"),
    variants_source=lambda: [
        (f"{arch}.{engine}", None, {}) for arch in _ARCHS for engine in _ENGINES
    ],
    run_factory=assert_outputs(_expectations),
)


def can_run(scenario: str, variant: str) -> bool:
    arch, engine = split_variant(variant)
    return scenario == "superh_isa" and arch in _ARCHS and engine in _ENGINES


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog=f"run_case.py {scenario} {variant}")
    parser.add_argument("program", choices=sorted(_PROGRAMS))
    ns = parser.parse_args(list(args))

    import smallworld

    arch, engine = split_variant(variant)
    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, ARCH_REGISTERS[arch].platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = smallworld.state.memory.code.Executable.from_bytes(
        _PROGRAMS[ns.program], address=0x1000
    )
    machine.add(code)
    cpu.pc.set(code.address)
    cpu.r1.set(_R1_IN)
    # dt writes the T bit; give sr a concrete value so it stays concrete.
    cpu.sr.set(0)

    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(code.address + code.get_capacity())
    try:
        final_cpu = machine.emulate(emulator).get_cpu()
    except smallworld.exceptions.EmulationExecInvalidFailure:
        print("illegal instruction")
        return 0
    # Fixed width, because the expected output is matched as a substring.
    print(f"r1={final_cpu.r1.get():#010x}")
    return 0
