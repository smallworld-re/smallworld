from __future__ import annotations

import argparse
import logging
from typing import Sequence

from .common import (
    PlatformSpec,
    concrete,
    load_raw_code,
    make_emulator,
    make_platform,
    split_variant,
)
from .spec import ScenarioInfo, assert_outputs

NATIVE_PARITY = False

# x86 real mode with segments that don't start at 0, which the other x86_16
# scenarios never leave. The recursion binary runs at 07c0:0000 (a boot
# sector's address), with its stack in a segment of its own, so near calls
# push offsets into cs, returns add them back onto it, and bp-relative
# arguments are read through ss.

_PLATFORM = PlatformSpec("X86_16", "LITTLE")
_CODE_SEGMENT = 0x07C0
_STACK_BASE = 0x9C00
_STACK_SIZE = 0x2000

# Sleigh infers cs from the linear pc as (pc >> 4) & 0xf000, which is wrong
# for any segment that doesn't start on a 64 KiB boundary; see the x86_16
# Ghidra machine definition.
_PCODE_SEGMENTS = "sleigh assumes code segments start on a 64 KiB boundary"

_VARIANTS = {
    "x86_16": None,
    "x86_16.angr": _PCODE_SEGMENTS,
    "x86_16.pcode": _PCODE_SEGMENTS,
}

SCENARIO_PREFIXES = (("real_mode", "real_mode"),)

SCENARIO_INFO = ScenarioInfo(
    prefix="real_mode",
    scenario="real_mode",
    tags=("scenario", "real_mode"),
    variants_source=lambda: [
        (variant, reason, {}) for variant, reason in _VARIANTS.items()
    ],
    run_factory=assert_outputs(
        tuple(
            ((str(number),), f"{expected:#x}")
            for number, expected in ((-1, 91), (100, 91), (102, 92))
        ),
    ),
)


def can_run(scenario: str, variant: str) -> bool:
    return scenario == "real_mode" and variant in _VARIANTS


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if _VARIANTS[variant] is not None:
        raise SystemExit(_VARIANTS[variant])
    parser = argparse.ArgumentParser(prog=f"run_case.py {scenario} {variant}")
    parser.add_argument("value", type=lambda text: int(text, 0), help="numeric input")
    ns = parser.parse_args(list(args))

    import smallworld

    _, engine = split_variant(variant)
    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, _PLATFORM)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, "recursion", "x86_16", address=_CODE_SEGMENT << 4)
    machine.add(code)
    cpu.cs.set(_CODE_SEGMENT)
    cpu.ds.set(_CODE_SEGMENT)
    cpu.es.set(_CODE_SEGMENT)
    cpu.pc.set(code.address)

    stack = smallworld.state.memory.stack.Stack.for_platform(
        platform, _STACK_BASE, _STACK_SIZE
    )
    machine.add(stack)
    stack.push_integer(ns.value, 2, None)
    stack.push_integer(0xFFFF, 2, "fake return address")
    cpu.ss.set(stack.get_segment())
    cpu.sp.set(stack.get_offset())

    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(code.address + code.get_capacity())
    final_cpu = machine.emulate(emulator).get_cpu()
    print(hex(concrete(final_cpu.ax.get())))
    return 0
