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
# scenarios never leave.
#
# real_mode runs the recursion binary with its stack in a segment of its
# own, so near calls push offsets into cs, returns add them back onto it,
# and bp-relative arguments are read through ss. The x86_16 variants put the
# code at 07c0:0000 (a boot sector's address); the x86_16_aligned ones put
# it at 1000:0000, which angr and Ghidra can run too.
#
# real_mode_ds runs the strlen binary with the string in a data segment of
# its own, so its pointer is an offset that is only read through ds.

_PLATFORM = PlatformSpec("X86_16", "LITTLE")
_STACK_BASE = 0x9C00
_STACK_SIZE = 0x2000

# Sleigh infers cs from the linear pc as (pc >> 4) & 0xf000, which is wrong
# for any segment that doesn't start on a 64 KiB boundary; see the x86_16
# Ghidra machine definition.
_PCODE_SEGMENTS = "sleigh assumes code segments start on a 64 KiB boundary"

# variant -> (code segment, skip reason)
_VARIANTS = {
    "x86_16": (0x07C0, None),
    "x86_16.angr": (0x07C0, _PCODE_SEGMENTS),
    "x86_16.pcode": (0x07C0, _PCODE_SEGMENTS),
    "x86_16_aligned": (0x1000, None),
    "x86_16_aligned.angr": (0x1000, None),
    "x86_16_aligned.pcode": (0x1000, None),
}

_DS_VARIANTS = {
    "x86_16": None,
    "x86_16.angr": None,
    "x86_16.pcode": None,
}
_DS_CODE_SEGMENT = 0x1000
_DATA_SEGMENT = 0x2000
_STRING_OFFSET = 0x0100

SCENARIO_PREFIXES = (("real_mode", "real_mode"), ("real_mode_ds", "real_mode_ds"))

SCENARIO_INFOS = (
    ScenarioInfo(
        prefix="real_mode",
        scenario="real_mode",
        tags=("scenario", "real_mode"),
        variants_source=lambda: [
            (variant, reason, {}) for variant, (_, reason) in _VARIANTS.items()
        ],
        run_factory=assert_outputs(
            tuple(
                ((str(number),), f"{expected:#x}")
                for number, expected in ((-1, 91), (100, 91), (102, 92))
            ),
        ),
    ),
    ScenarioInfo(
        prefix="real_mode_ds",
        scenario="real_mode_ds",
        tags=("scenario", "real_mode"),
        variants_source=lambda: [
            (variant, reason, {}) for variant, reason in _DS_VARIANTS.items()
        ],
        run_factory=assert_outputs(
            (
                (("",), "0x0"),
                (("foobar",), "0x6"),
            ),
        ),
    ),
)


def can_run(scenario: str, variant: str) -> bool:
    if scenario == "real_mode":
        return variant in _VARIANTS
    if scenario == "real_mode_ds":
        return variant in _DS_VARIANTS
    return False


def _check_pc(final_cpu, cs: int, expected: int) -> None:
    """Fail unless the run stopped at `expected` in segment `cs`."""
    pc = concrete(final_cpu.pc.get())
    if pc != expected:
        raise SystemExit(f"final pc {pc} != {expected:#x}")
    if concrete(final_cpu.cs.get()) != cs:
        raise SystemExit(f"final cs {final_cpu.cs.get()} != {cs:#x}")
    # eip only exists on Unicorn.
    ip = concrete(final_cpu.ip.get())
    if ip is not None and ip != expected - (cs << 4):
        raise SystemExit(f"final ip {ip} != {expected - (cs << 4):#x}")


def _set_stack(smallworld, platform, machine, cpu):
    stack = smallworld.state.memory.stack.Stack.for_platform(
        platform, _STACK_BASE, _STACK_SIZE
    )
    machine.add(stack)
    cpu.ss.set(stack.get_segment())
    return stack


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if scenario == "real_mode_ds":
        return _run_ds_case(variant, args)
    code_segment, reason = _VARIANTS[variant]
    if reason is not None:
        raise SystemExit(reason)
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

    code = load_raw_code(smallworld, "recursion", "x86_16", address=code_segment << 4)
    machine.add(code)
    cpu.cs.set(code_segment)
    cpu.ds.set(code_segment)
    cpu.es.set(code_segment)
    cpu.pc.set(code.address)

    stack = _set_stack(smallworld, platform, machine, cpu)
    stack.push_integer(ns.value, 2, None)
    stack.push_integer(0xFFFF, 2, "fake return address")
    cpu.sp.set(stack.get_offset())

    emulator = make_emulator(smallworld, platform, engine)
    exit_point = code.address + code.get_capacity()
    emulator.add_exit_point(exit_point)
    final_cpu = machine.emulate(emulator).get_cpu()
    _check_pc(final_cpu, code_segment, exit_point)
    print(hex(concrete(final_cpu.ax.get())))
    return 0


def _run_ds_case(variant: str, args: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog=f"run_case.py real_mode_ds {variant}")
    parser.add_argument("value", help="string input")
    ns = parser.parse_args(list(args))

    import smallworld

    _, engine = split_variant(variant)
    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, _PLATFORM)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, "strlen", "x86_16", address=_DS_CODE_SEGMENT << 4)
    machine.add(code)
    cpu.cs.set(_DS_CODE_SEGMENT)
    cpu.pc.set(code.address)

    # The string is in a data segment of its own; read without ds, its
    # offset is unmapped.
    data = smallworld.state.memory.RawMemory.from_bytes(
        ns.value.encode("utf-8") + b"\0", (_DATA_SEGMENT << 4) + _STRING_OFFSET
    )
    machine.add(data)
    cpu.ds.set(_DATA_SEGMENT)

    stack = _set_stack(smallworld, platform, machine, cpu)
    stack.push_integer(_STRING_OFFSET, 2, "string pointer")
    stack.push_integer(0xFFFF, 2, "fake return address")
    cpu.sp.set(stack.get_offset())

    emulator = make_emulator(smallworld, platform, engine)
    exit_point = code.address + code.get_capacity()
    emulator.add_exit_point(exit_point)
    final_cpu = machine.emulate(emulator).get_cpu()
    _check_pc(final_cpu, _DS_CODE_SEGMENT, exit_point)
    print(hex(concrete(final_cpu.ax.get())))
    return 0
