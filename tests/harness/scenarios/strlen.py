from __future__ import annotations

import argparse
import dataclasses
import logging
from typing import Sequence

from .common import (
    PlatformSpec,
    build_specs,
    load_raw_code,
    make_emulator,
    make_platform,
    set_register,
    split_variant,
)
from .spec import ScenarioInfo, assert_outputs, from_arch_table

NATIVE_PARITY = True


@dataclasses.dataclass(frozen=True)
class StrlenSpec:
    platform: PlatformSpec
    pc_register: str
    result_register: str
    engines: tuple[str, ...]
    stack_pointer_register: str
    return_address_size: int
    arg_register: str | None = None
    stack_argument_size: int | None = None
    print_stack: bool = False
    print_address: bool = False


_ARCHS = (
    "aarch64",
    "amd64",
    "armel",
    "armhf",
    "i386",
    "la64",
    "m68k",
    "mips",
    "mipsel",
    "mips64",
    "mips64el",
    "ppc",
    "ppc64",
    "riscv64",
    "tricore",
    "xtensa",
)

_ARM_ENGINES = ("unicorn", "angr", "panda", "pcode", "styx")
# PowerPC also runs on Styx: "styx" selects the PPC405 core, "styx-mpc860" the MPC860.
_PPC_ENGINES = _ARM_ENGINES + ("styx-mpc860",)

_SPECS = build_specs(
    StrlenSpec,
    _ARCHS,
    field_aliases={"return_address_size": "pointer_size"},
    engines={"armel": _ARM_ENGINES, "armhf": _ARM_ENGINES, "ppc": _PPC_ENGINES},
    per_arch={
        # i386 and m68k take the string pointer on the stack rather than in a reg.
        "i386": {"arg_register": None, "stack_argument_size": 4},
        "m68k": {"arg_register": None, "stack_argument_size": 4},
        # tricore receives a pointer in a4, not the canonical integer-arg d4.
        "tricore": {"arg_register": "a4"},
        # Only amd64 prints the stack and pointer address; others print result only.
        "amd64": {"print_stack": True, "print_address": True},
    },
)


SCENARIO_PREFIXES = (("strlen", "strlen"),)

SCENARIO_INFO = ScenarioInfo(
    prefix="strlen",
    scenario="strlen",
    tags=("scenario", "strlen"),
    variants_source=from_arch_table(
        _SPECS,
        skip_reasons={"ppc64": "Unicorn ppc64 support buggy"},
    ),
    run_factory=assert_outputs(
        (
            (("",), "0x0"),
            (("foobar",), "0x6"),
        ),
    ),
)


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "strlen":
        return False
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog=f"run_case.py {scenario} {variant}")
    parser.add_argument("value", help="string input")
    ns = parser.parse_args(list(args))

    import smallworld

    arch, engine = split_variant(variant)
    spec = _SPECS[arch]

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, "strlen", arch)
    machine.add(code)
    set_register(cpu, spec.pc_register, code.address)

    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
    machine.add(stack)

    string = ns.value.encode("utf-8") + b"\0"
    padding = b"\0" * (16 - (len(string) % 16))
    stack.push_bytes(string + padding, None)
    if spec.print_stack:
        print(stack)

    saddr = stack.get_pointer()
    if spec.print_address:
        print(hex(saddr))

    if spec.stack_argument_size is not None:
        stack.push_integer(saddr, spec.stack_argument_size, None)

    stack.push_integer(0x00000000, spec.return_address_size, None)
    set_register(cpu, spec.stack_pointer_register, stack.get_pointer())

    if spec.arg_register is not None:
        set_register(cpu, spec.arg_register, saddr)

    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(code.address + code.get_capacity())

    final_machine = machine.emulate(emulator)
    print(hex(getattr(final_machine.get_cpu(), spec.result_register).get()))
    return 0
