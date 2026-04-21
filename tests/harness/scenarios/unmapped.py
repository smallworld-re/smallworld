from __future__ import annotations

import dataclasses
import logging
from typing import Sequence

from .common import (
    PlatformSpec,
    load_elf_code,
    make_emulator,
    make_platform,
    maybe_enable_linear,
    set_register,
    split_variant,
)


@dataclasses.dataclass(frozen=True)
class UnmappedSpec:
    platform: PlatformSpec
    pc_register: str
    engines: tuple[str, ...]
    load_address: int | None = None
    stack_pointer_register: str = "sp"
    entrypoint_registers: tuple[str, ...] = ()
    stack_padding_bytes: int = 0


_SPECS = {
    "aarch64": UnmappedSpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        pc_register="pc",
        engines=("unicorn", "angr", "pcode"),
        load_address=0x400000,
    ),
    "amd64": UnmappedSpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pc_register="rip",
        engines=("unicorn", "angr", "pcode"),
        load_address=0x400000,
        stack_pointer_register="rsp",
    ),
    "armel": UnmappedSpec(
        platform=PlatformSpec("ARM_V6M", "LITTLE"),
        pc_register="pc",
        engines=("unicorn", "angr", "pcode"),
    ),
    "armhf": UnmappedSpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pc_register="pc",
        engines=("unicorn", "angr", "pcode"),
        load_address=0x4000000,
    ),
    "i386": UnmappedSpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        pc_register="eip",
        engines=("unicorn", "angr", "pcode"),
        load_address=0x400000,
        stack_pointer_register="esp",
    ),
    "la64": UnmappedSpec(
        platform=PlatformSpec("LOONGARCH64", "LITTLE"),
        pc_register="pc",
        engines=("angr", "pcode"),
    ),
    "m68k": UnmappedSpec(
        platform=PlatformSpec("M68K", "BIG"),
        pc_register="pc",
        engines=("unicorn", "pcode"),
        load_address=0x40000,
    ),
    "mips": UnmappedSpec(
        platform=PlatformSpec("MIPS32", "BIG"),
        pc_register="pc",
        engines=("unicorn", "angr", "pcode"),
        entrypoint_registers=("t9",),
    ),
    "mipsel": UnmappedSpec(
        platform=PlatformSpec("MIPS32", "LITTLE"),
        pc_register="pc",
        engines=("unicorn", "angr", "pcode"),
        entrypoint_registers=("t9",),
    ),
    "mips64": UnmappedSpec(
        platform=PlatformSpec("MIPS64", "BIG"),
        pc_register="pc",
        engines=("unicorn", "angr", "pcode"),
        entrypoint_registers=("t9",),
    ),
    "mips64el": UnmappedSpec(
        platform=PlatformSpec("MIPS64", "LITTLE"),
        pc_register="pc",
        engines=("unicorn", "angr", "pcode"),
        entrypoint_registers=("t9",),
    ),
    "ppc": UnmappedSpec(
        platform=PlatformSpec("POWERPC32", "BIG"),
        pc_register="pc",
        engines=("unicorn", "angr", "pcode"),
        stack_padding_bytes=32,
    ),
    "ppc64": UnmappedSpec(
        platform=PlatformSpec("POWERPC64", "BIG"),
        pc_register="pc",
        engines=("angr", "pcode"),
        load_address=0x400000,
        stack_padding_bytes=32,
    ),
    "riscv64": UnmappedSpec(
        platform=PlatformSpec("RISCV64", "LITTLE"),
        pc_register="pc",
        engines=("unicorn", "angr", "pcode"),
        load_address=0x400000,
    ),
    "tricore": UnmappedSpec(
        platform=PlatformSpec("TRICORE", "LITTLE"),
        pc_register="pc",
        engines=("angr", "pcode"),
    ),
}

_SKIP_REASONS = {
    "aarch64.panda": "Waiting for panda-ng",
    "amd64.panda": "Waiting for panda-ng",
    "armel.panda": "Waiting for panda-ng",
    "armhf.panda": "Waiting for panda-ng",
    "i386.panda": "Waiting for panda-ng",
    "mips.panda": "Waiting for panda-ng",
    "mips64.panda": "Waiting for panda-ng",
    "mips64el.panda": "Waiting for panda-ng",
    "mipsel.panda": "Waiting for panda-ng",
    "ppc.panda": "Waiting for panda-ng",
    "ppc64": "Unicorn ppc64 support buggy",
}


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "unmapped":
        return False
    if variant in _SKIP_REASONS:
        return True
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def _build_machine(smallworld, arch: str, engine: str, spec: UnmappedSpec):
    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_elf_code(
        smallworld,
        "unmapped",
        arch,
        platform,
        address=spec.load_address,
    )
    machine.add(code)

    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
    machine.add(stack)
    if spec.stack_padding_bytes:
        # PowerPC keeps ABI scratch data above SP, so the old tests reserved it first.
        stack.push_bytes(b"\0" * spec.stack_padding_bytes, None)
    set_register(cpu, spec.stack_pointer_register, stack.get_pointer())

    if engine == "unicorn":
        machine.add_exit_point(0)

    return machine, cpu, platform, code


def _run_operation(
    smallworld,
    arch: str,
    engine: str,
    spec: UnmappedSpec,
    symbol: str,
    expected_exception,
) -> None:
    machine, cpu, platform, code = _build_machine(smallworld, arch, engine, spec)
    entrypoint = code.get_symbol_value(symbol)
    set_register(cpu, spec.pc_register, entrypoint)
    for register_name in spec.entrypoint_registers:
        set_register(cpu, register_name, entrypoint)

    emulator = make_emulator(smallworld, platform, engine)
    maybe_enable_linear(smallworld, emulator, engine)
    if engine == "angr" and isinstance(emulator, smallworld.emulators.AngrEmulator):
        emulator.error_on_unmapped = True

    try:
        machine.emulate(emulator)
    except expected_exception:
        return
    raise RuntimeError(f"Did not report {symbol.replace('_', ' ')}")


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if args:
        raise SystemExit(f"{scenario} does not take extra arguments: {' '.join(args)}")
    if variant in _SKIP_REASONS:
        raise SystemExit(_SKIP_REASONS[variant])

    import smallworld

    arch, engine = split_variant(variant)
    spec = _SPECS[arch]

    smallworld.logging.setup_logging(level=logging.INFO)

    operations = (
        ("read_unmapped", smallworld.exceptions.EmulationReadUnmappedFailure, "Read"),
        (
            "write_unmapped",
            smallworld.exceptions.EmulationWriteUnmappedFailure,
            "Write",
        ),
        (
            "fetch_unmapped",
            smallworld.exceptions.EmulationFetchUnmappedFailure,
            "Fetch",
        ),
    )
    for symbol, expected_exception, label in operations:
        _run_operation(smallworld, arch, engine, spec, symbol, expected_exception)
        print(f"{label} SUCCESS")
    return 0
