from __future__ import annotations

import dataclasses
import logging
from typing import Sequence

from .common import (
    PlatformSpec,
    StringSource,
    load_raw_code,
    make_emulator,
    make_gets_model,
    make_platform,
    make_puts_model,
    maybe_enable_linear,
    read_c_string,
    resolve_string_pointer,
    set_register,
    split_variant,
)


@dataclasses.dataclass(frozen=True)
class HookingSpec:
    platform: PlatformSpec
    pointer_size: int
    pc_register: str
    stack_pointer_register: str
    pc_offset: int
    engines: tuple[str, ...]
    string_source: StringSource
    gets_address: int = 0x1000
    puts_address: int = 0x1004
    stack_base: int = 0x2000
    stack_padding_bytes: dict[str, int] = dataclasses.field(default_factory=dict)


_SPECS = {
    "aarch64": HookingSpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        pc_offset=8,
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(register="x0"),
    ),
    "amd64": HookingSpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pointer_size=8,
        pc_register="rip",
        stack_pointer_register="rsp",
        pc_offset=0,
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(register="rdi"),
        gets_address=0x3800,
        puts_address=0x3808,
        stack_base=0x8000,
    ),
    "armel": HookingSpec(
        platform=PlatformSpec("ARM_V6M", "LITTLE"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        pc_offset=8,
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(register="r0"),
    ),
    "armhf": HookingSpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        pc_offset=8,
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(register="r0"),
    ),
    "i386": HookingSpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        pointer_size=4,
        pc_register="eip",
        stack_pointer_register="esp",
        pc_offset=2,
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(
            stack_pointer_register="esp",
            stack_offset=4,
            pointer_size=4,
            byteorder="little",
        ),
        puts_address=0x1001,
    ),
    "la64": HookingSpec(
        platform=PlatformSpec("LOONGARCH64", "LITTLE"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        pc_offset=8,
        engines=("angr", "pcode"),
        string_source=StringSource(register="a0"),
    ),
    "m68k": HookingSpec(
        platform=PlatformSpec("M68K", "BIG"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        pc_offset=4,
        engines=("unicorn", "pcode"),
        string_source=StringSource(
            stack_pointer_register="sp",
            stack_offset=4,
            pointer_size=4,
            byteorder="big",
        ),
        puts_address=0x1002,
    ),
    "mips": HookingSpec(
        platform=PlatformSpec("MIPS32", "BIG"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        pc_offset=8,
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(register="a0"),
    ),
    "mips64": HookingSpec(
        platform=PlatformSpec("MIPS64", "BIG"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        pc_offset=8,
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(register="a0"),
    ),
    "mips64el": HookingSpec(
        platform=PlatformSpec("MIPS64", "LITTLE"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        pc_offset=8,
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(register="a0"),
    ),
    "mipsel": HookingSpec(
        platform=PlatformSpec("MIPS32", "LITTLE"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        pc_offset=8,
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(register="a0"),
    ),
    "ppc": HookingSpec(
        platform=PlatformSpec("POWERPC32", "BIG"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        pc_offset=8,
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(register="r3"),
        stack_padding_bytes={"unicorn": 8, "angr": 8, "panda": 8, "pcode": 8},
    ),
    "ppc64": HookingSpec(
        platform=PlatformSpec("POWERPC64", "BIG"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        pc_offset=8,
        engines=("angr", "pcode"),
        string_source=StringSource(register="r3"),
        stack_padding_bytes={"pcode": 16},
    ),
    "riscv64": HookingSpec(
        platform=PlatformSpec("RISCV64", "LITTLE"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        pc_offset=8,
        engines=("unicorn", "angr", "pcode"),
        string_source=StringSource(register="a0"),
        puts_address=0x1002,
    ),
    "tricore": HookingSpec(
        platform=PlatformSpec("TRICORE", "LITTLE"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        pc_offset=8,
        engines=("angr", "panda", "pcode"),
        string_source=StringSource(register="a4"),
    ),
    "xtensa": HookingSpec(
        platform=PlatformSpec("XTENSA", "LITTLE"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        pc_offset=8,
        engines=("angr", "pcode"),
        string_source=StringSource(register="a2"),
    ),
}

_SKIP_REASONS = {
    "ppc64": "Unicorn ppc64 support buggy",
}


def _install_tricore_panda_callsite_hooks(smallworld, machine, code, spec) -> None:
    def skip_current_call(emulator: smallworld.emulators.Emulator) -> None:
        pc = emulator.read_register(spec.pc_register)
        emulator.write_register(spec.pc_register, pc + emulator.current_instruction().size)

    def gets_hook(emulator: smallworld.emulators.Emulator) -> None:
        pointer = resolve_string_pointer(emulator, spec.string_source)
        data = input().encode("utf-8") + b"\0"
        emulator.write_memory_content(pointer, data)
        skip_current_call(emulator)

    def puts_hook(emulator: smallworld.emulators.Emulator) -> None:
        pointer = resolve_string_pointer(emulator, spec.string_source)
        print(read_c_string(emulator, pointer))
        skip_current_call(emulator)

    machine.add(smallworld.state.models.Hook(code.address + 0x0C, gets_hook))
    machine.add(smallworld.state.models.Hook(code.address + 0x12, puts_hook))


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "hooking":
        return False
    if variant in _SKIP_REASONS:
        return True
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if args:
        raise SystemExit(f"{scenario} does not take extra arguments: {' '.join(args)}")
    if variant in _SKIP_REASONS:
        raise SystemExit(_SKIP_REASONS[variant])

    import smallworld

    arch, engine = split_variant(variant)
    spec = _SPECS[arch]

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, "hooking", arch)
    machine.add(code)

    stack = smallworld.state.memory.stack.Stack.for_platform(
        platform, spec.stack_base, 0x4000
    )
    machine.add(stack)
    padding = spec.stack_padding_bytes.get(engine, 0)
    if padding:
        stack.push_bytes(b"\0" * padding, "Scratch space")

    set_register(cpu, spec.pc_register, code.address + spec.pc_offset)
    stack.push_integer(0xFFFFFFFF, spec.pointer_size, "fake return address")
    set_register(cpu, spec.stack_pointer_register, stack.get_pointer())

    if arch == "tricore" and engine == "panda":
        _install_tricore_panda_callsite_hooks(smallworld, machine, code, spec)
    else:
        machine.add(
            make_gets_model(
                smallworld,
                platform=platform,
                address=spec.gets_address,
                destination=spec.string_source,
            )
        )
        machine.add(
            make_puts_model(
                smallworld,
                platform=platform,
                address=spec.puts_address,
                source=spec.string_source,
            )
        )

    emulator = make_emulator(smallworld, platform, engine)
    maybe_enable_linear(smallworld, emulator, engine)
    emulator.add_exit_point(code.address + code.get_capacity())
    machine.emulate(emulator)
    return 0
