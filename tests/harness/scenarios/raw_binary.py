from __future__ import annotations

import argparse
import dataclasses
import logging
from typing import Literal, Mapping, Sequence

from .common import (
    install_tricore_panda_shadow_returns,
    PlatformSpec,
    load_raw_code,
    make_emulator,
    make_platform,
    maybe_enable_linear,
    set_register,
    split_variant,
)

PrintMode = Literal["hex", "register"]


@dataclasses.dataclass(frozen=True)
class StackSpec:
    # Most of these old tests only differed in how they prepared the stack.
    pointer_register: str
    base: int = 0x2000
    size: int = 0x4000
    fake_return: int = 0xFFFFFFFF
    fake_return_size: int = 8
    argument_size: int | None = None
    pointer_adjust: int = 0


@dataclasses.dataclass(frozen=True)
class RawBinarySpec:
    # This is the full shape of one architecture-specific runner variant.
    platform: PlatformSpec
    pc_register: str
    result_register: str
    engines: tuple[str, ...]
    entry_offset: int = 0
    arg_register: str | None = None
    print_mode: PrintMode = "hex"
    stack: StackSpec | None = None
    print_exit_point: bool = False


def parse_integer_argument(
    family: str,
    variant: str,
    args: Sequence[str],
) -> int:
    parser = argparse.ArgumentParser(prog=f"run_case.py {family} {variant}")
    parser.add_argument("value", type=lambda text: int(text, 0), help="numeric input")
    return parser.parse_args(list(args)).value


def supports_variant(variant: str, specs: Mapping[str, RawBinarySpec]) -> bool:
    arch, engine = split_variant(variant)
    return arch in specs and engine in specs[arch].engines


def _configure_stack(
    smallworld, machine, cpu, platform, spec: RawBinarySpec, argument: int
) -> None:
    if spec.stack is None:
        return

    stack = smallworld.state.memory.stack.Stack.for_platform(
        platform, spec.stack.base, spec.stack.size
    )
    machine.add(stack)

    # i386 passes the first argument on the stack; the other migrated families
    # still use registers and only need the synthetic return address.
    if spec.stack.argument_size is not None:
        stack.push_integer(argument, spec.stack.argument_size, None)

    if spec.stack.fake_return_size is not None:
        stack.push_integer(
            spec.stack.fake_return,
            spec.stack.fake_return_size,
            "fake return address",
        )

    set_register(
        cpu,
        spec.stack.pointer_register,
        stack.get_pointer() + spec.stack.pointer_adjust,
    )


def _print_result(cpu, spec: RawBinarySpec) -> None:
    register = getattr(cpu, spec.result_register)
    if spec.print_mode == "register":
        print(register)
        return
    print(hex(register.get()))


def run_integer_case(
    family: str,
    variant: str,
    args: Sequence[str],
    specs: Mapping[str, RawBinarySpec],
) -> int:
    import smallworld

    argument = parse_integer_argument(family, variant, args)
    arch, engine = split_variant(variant)
    spec = specs[arch]

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, family, arch)
    machine.add(code)
    set_register(cpu, spec.pc_register, code.address + spec.entry_offset)

    if spec.arg_register is not None:
        set_register(cpu, spec.arg_register, argument)

    _configure_stack(smallworld, machine, cpu, platform, spec, argument)

    emulator = make_emulator(smallworld, platform, engine)
    maybe_enable_linear(smallworld, emulator, engine)
    if arch == "tricore" and engine == "panda":
        install_tricore_panda_shadow_returns(emulator, code)

    exit_point = code.address + code.get_capacity()
    emulator.add_exit_point(exit_point)
    if spec.print_exit_point:
        print(f"exiting at {exit_point}")

    final_machine = machine.emulate(emulator)
    _print_result(final_machine.get_cpu(), spec)
    return 0
