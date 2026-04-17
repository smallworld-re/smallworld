from __future__ import annotations

import dataclasses
import logging
from typing import Sequence

from .common import (
    PlatformSpec,
    load_raw_code,
    make_emulator,
    make_platform,
    maybe_enable_linear,
    set_register,
    split_variant,
)


@dataclasses.dataclass(frozen=True)
class StaticBufferSpec:
    platform: PlatformSpec
    pc_register: str
    result_register: str
    model_register: str
    engines: tuple[str, ...]
    entry_offset: int
    stack_pointer_register: str
    stack_pointer_adjust: int = 0
    model_address: int | None = None
    model_code_offset: int | None = None
    exit_offset: int | None = None


_SPECS = {
    "aarch64": StaticBufferSpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        pc_register="pc",
        result_register="w0",
        model_register="x0",
        engines=("unicorn", "angr", "panda", "pcode"),
        entry_offset=4,
        stack_pointer_register="sp",
        model_address=0x1000,
    ),
    "amd64": StaticBufferSpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pc_register="rip",
        result_register="eax",
        model_register="rax",
        engines=("unicorn", "angr", "panda", "pcode"),
        entry_offset=0,
        stack_pointer_register="rsp",
        model_code_offset=0x2800,
    ),
    "armel": StaticBufferSpec(
        platform=PlatformSpec("ARM_V5T", "LITTLE"),
        pc_register="pc",
        result_register="r0",
        model_register="r0",
        engines=("unicorn", "angr", "panda", "pcode"),
        entry_offset=4,
        stack_pointer_register="sp",
        model_address=0x1000,
    ),
    "armhf": StaticBufferSpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pc_register="pc",
        result_register="r0",
        model_register="r0",
        engines=("unicorn", "angr", "panda", "pcode"),
        entry_offset=4,
        stack_pointer_register="sp",
        model_address=0x1000,
    ),
    "i386": StaticBufferSpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        pc_register="eip",
        result_register="eax",
        model_register="eax",
        engines=("unicorn", "angr", "panda", "pcode"),
        entry_offset=4,
        stack_pointer_register="esp",
        model_address=0x1000,
    ),
    "la64": StaticBufferSpec(
        platform=PlatformSpec("LOONGARCH64", "LITTLE"),
        pc_register="pc",
        result_register="a0",
        model_register="a0",
        engines=("angr", "pcode"),
        entry_offset=4,
        stack_pointer_register="sp",
        model_address=0x1000,
    ),
    "m68k": StaticBufferSpec(
        platform=PlatformSpec("M68K", "BIG"),
        pc_register="pc",
        result_register="d0",
        model_register="a0",
        engines=("unicorn", "pcode"),
        entry_offset=2,
        stack_pointer_register="sp",
        model_address=0x1000,
    ),
    "mips": StaticBufferSpec(
        platform=PlatformSpec("MIPS32", "BIG"),
        pc_register="pc",
        result_register="v0",
        model_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        entry_offset=4,
        stack_pointer_register="sp",
        model_address=0x1000,
    ),
    "mipsel": StaticBufferSpec(
        platform=PlatformSpec("MIPS32", "LITTLE"),
        pc_register="pc",
        result_register="v0",
        model_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        entry_offset=4,
        stack_pointer_register="sp",
        model_address=0x1000,
    ),
    "mips64": StaticBufferSpec(
        platform=PlatformSpec("MIPS64", "BIG"),
        pc_register="pc",
        result_register="v0",
        model_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        entry_offset=4,
        stack_pointer_register="sp",
        model_address=0x1000,
    ),
    "mips64el": StaticBufferSpec(
        platform=PlatformSpec("MIPS64", "LITTLE"),
        pc_register="pc",
        result_register="v0",
        model_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        entry_offset=4,
        stack_pointer_register="sp",
        model_address=0x1000,
    ),
    "ppc": StaticBufferSpec(
        platform=PlatformSpec("POWERPC32", "BIG"),
        pc_register="pc",
        result_register="r3",
        model_register="r3",
        engines=("unicorn", "angr", "panda", "pcode"),
        entry_offset=4,
        stack_pointer_register="sp",
        model_address=0x1000,
    ),
    "ppc64": StaticBufferSpec(
        platform=PlatformSpec("POWERPC64", "BIG"),
        pc_register="pc",
        result_register="r3",
        model_register="r3",
        engines=("unicorn", "angr", "pcode"),
        entry_offset=4,
        stack_pointer_register="sp",
        stack_pointer_adjust=-0x80,
        model_address=0x1000,
    ),
    "riscv64": StaticBufferSpec(
        platform=PlatformSpec("RISCV64", "LITTLE"),
        pc_register="pc",
        result_register="a0",
        model_register="a0",
        engines=("unicorn", "angr", "pcode"),
        entry_offset=2,
        stack_pointer_register="sp",
        model_address=0x1000,
    ),
    "tricore": StaticBufferSpec(
        platform=PlatformSpec("TRICORE", "LITTLE"),
        pc_register="pc",
        result_register="d2",
        model_register="a2",
        engines=("angr", "pcode"),
        entry_offset=4,
        stack_pointer_register="sp",
        model_address=0x1000,
    ),
    "xtensa": StaticBufferSpec(
        platform=PlatformSpec("XTENSA", "LITTLE"),
        pc_register="pc",
        result_register="a2",
        model_register="a2",
        engines=("angr", "pcode"),
        entry_offset=4,
        stack_pointer_register="sp",
        model_address=0x1000,
        exit_offset=0xA,
    ),
}


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "static_buf":
        return False
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if args:
        raise SystemExit(f"{scenario} does not take extra arguments: {' '.join(args)}")

    import smallworld

    arch, engine = split_variant(variant)
    spec = _SPECS[arch]

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, "static_buf", arch)
    machine.add(code)

    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
    machine.add(stack)

    set_register(cpu, spec.pc_register, code.address + spec.entry_offset)
    stack.push_integer(0xFFFFFFFF, 8, "fake return address")
    set_register(
        cpu,
        spec.stack_pointer_register,
        stack.get_pointer() + spec.stack_pointer_adjust,
    )

    static_buffer_address = 0x10000
    model_address = (
        spec.model_address
        if spec.model_address is not None
        else code.address + (spec.model_code_offset or 0)
    )
    platform_value = platform
    abi_value = smallworld.platforms.ABI.NONE

    class FoobarModel(smallworld.state.models.Model):
        name = "foobar"
        platform = platform_value
        abi = abi_value
        static_space_required = 4

        def model(self, emulator: smallworld.emulators.Emulator) -> None:
            data = 0x04A1.to_bytes(
                4,
                (
                    "little"
                    if platform.byteorder == smallworld.platforms.Byteorder.LITTLE
                    else "big"
                ),
            )
            emulator.write_memory(static_buffer_address, data)
            emulator.write_register(spec.model_register, static_buffer_address)

    foobar = FoobarModel(model_address)
    foobar.static_buffer_address = static_buffer_address
    machine.add(foobar)

    emulator = make_emulator(smallworld, platform, engine)
    maybe_enable_linear(smallworld, emulator, engine)
    if spec.exit_offset is not None:
        emulator.add_exit_point(code.address + spec.exit_offset)
    else:
        emulator.add_exit_point(code.address + code.get_capacity())

    final_machine = machine.emulate(emulator)
    result = getattr(final_machine.get_cpu(), spec.result_register).get()
    if not isinstance(result, int):
        result = emulator.eval_atmost(result, 1)[0]
    print(hex(result))
    return 0
