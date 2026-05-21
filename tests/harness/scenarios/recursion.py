from __future__ import annotations

import argparse
import dataclasses
import logging
from typing import Any, Sequence

from .common import (
    ARCH_REGISTERS,
    PlatformSpec,
    build_specs,
    load_raw_code,
    make_emulator,
    make_platform,
    set_register,
    split_variant,
)
from .spec import ScenarioInfo, assert_outputs, from_arch_table
from .tricore_panda import install_tricore_panda_raw_binary_call_return_compatibility

NATIVE_PARITY = True


@dataclasses.dataclass(frozen=True)
class StackItem:
    value: int | str
    size: int
    label: str | None = None


@dataclasses.dataclass(frozen=True)
class RecursionSpec:
    platform: PlatformSpec
    pc_register: str
    result_register: str
    engines: tuple[str, ...]
    entry_offset: int = 0
    arg_register: str | None = None
    stack_pointer_register: str = "sp"
    stack_items: tuple[StackItem, ...] = ()
    stack_pointer_adjust: int = 0


def _fake_return(arch: str, label: str = "fake return address") -> StackItem:
    return StackItem(0xFFFFFFFF, ARCH_REGISTERS[arch].pointer_size, label)


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

_PER_ARCH: dict[str, dict[str, Any]] = {
    "aarch64": {"stack_items": (_fake_return("aarch64"),), "stack_pointer_adjust": 8},
    "amd64": {"stack_items": (_fake_return("amd64"),)},
    "armel": {"stack_items": (_fake_return("armel"),)},
    "armhf": {"stack_items": (_fake_return("armhf"),)},
    # i386 and m68k pass the argument on the stack rather than in a register.
    "i386": {
        "arg_register": None,
        "stack_items": (StackItem("argument", 4), _fake_return("i386")),
    },
    "la64": {"stack_items": (_fake_return("la64"),)},
    "m68k": {
        "arg_register": None,
        "stack_items": (StackItem("argument", 4), _fake_return("m68k")),
    },
    "mips": {"stack_items": (_fake_return("mips"),)},
    "mipsel": {"stack_items": (_fake_return("mipsel"),)},
    "mips64": {"stack_items": (_fake_return("mips64"),)},
    "mips64el": {"stack_items": (_fake_return("mips64el"),)},
    "ppc": {
        "stack_items": (
            StackItem(0xFFFFFFFF, 4, "placeholder for lr"),
            StackItem(0xFFFFFFFF, 4, "empty space"),
        ),
    },
    "ppc64": {
        "stack_items": (_fake_return("ppc64"),),
        "stack_pointer_adjust": -0x80,
    },
    "riscv64": {
        "stack_items": (_fake_return("riscv64"),),
        "stack_pointer_adjust": 8,
    },
    "tricore": {"entry_offset": 0x38},
    "xtensa": {"stack_items": (_fake_return("xtensa"),)},
}

_ARM_ENGINES = ("unicorn", "angr", "panda", "pcode", "styx")

_SPECS = build_specs(
    RecursionSpec,
    _ARCHS,
    engines={"armel": _ARM_ENGINES, "armhf": _ARM_ENGINES},
    per_arch=_PER_ARCH,
)

SCENARIO_PREFIXES = (("recursion", "recursion"),)

SCENARIO_INFO = ScenarioInfo(
    prefix="recursion",
    scenario="recursion",
    tags=("scenario", "recursion"),
    variants_source=from_arch_table(
        _SPECS,
        skip_reasons={"ppc64": "Unicorn ppc64 support buggy"},
    ),
    run_factory=assert_outputs(
        tuple(
            ((str(number),), f"{expected:#x}")
            for number, expected in (
                (-1, 91),
                (0, 91),
                (100, 91),
                (101, 91),
                (102, 92),
            )
        ),
    ),
)


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "recursion":
        return False
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog=f"run_case.py {scenario} {variant}")
    parser.add_argument("value", type=lambda text: int(text, 0), help="numeric input")
    ns = parser.parse_args(list(args))

    import smallworld

    arch, engine = split_variant(variant)
    spec = _SPECS[arch]

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, "recursion", arch)
    machine.add(code)
    set_register(cpu, spec.pc_register, code.address + spec.entry_offset)

    if spec.arg_register is not None:
        set_register(cpu, spec.arg_register, ns.value)

    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
    machine.add(stack)
    for item in spec.stack_items:
        value = ns.value if item.value == "argument" else item.value
        stack.push_integer(value, item.size, item.label)
    set_register(
        cpu,
        spec.stack_pointer_register,
        stack.get_pointer() + spec.stack_pointer_adjust,
    )

    emulator = make_emulator(smallworld, platform, engine)
    install_tricore_panda_raw_binary_call_return_compatibility(
        arch, engine, emulator, code
    )
    emulator.add_exit_point(code.address + code.get_capacity())
    final_cpu = machine.emulate(emulator).get_cpu()
    print(hex(getattr(final_cpu, spec.result_register).get()))
    return 0
