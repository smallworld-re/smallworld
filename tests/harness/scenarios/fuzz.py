from __future__ import annotations

import argparse
import dataclasses
import logging
from typing import Optional, Sequence

from .common import PlatformSpec, TestsPath, make_emulator, make_platform


@dataclasses.dataclass(frozen=True)
class _FuzzSpec:
    platform: PlatformSpec
    pc_register: str
    result_register: str
    exit_offset: int
    engine: str
    arg_register: Optional[str] = None
    binary_name: Optional[str] = None
    heap_base: int = 0x2000
    heap_size: int = 0x1000
    stack_base: Optional[int] = None
    stack_size: Optional[int] = None
    fake_return: Optional[int] = None
    argument_size: int = 4
    print_raw_value: bool = False


_SIMPLE_SPECS = {
    "aarch64": _FuzzSpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        pc_register="pc",
        arg_register="x0",
        result_register="x1",
        exit_offset=92,
        engine="unicorn",
    ),
    "amd64": _FuzzSpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pc_register="rip",
        arg_register="rdi",
        result_register="eax",
        exit_offset=55,
        engine="unicorn",
    ),
    "amd64.panda": _FuzzSpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pc_register="rip",
        arg_register="rdi",
        result_register="eax",
        exit_offset=55,
        engine="panda",
        print_raw_value=True,
    ),
    "armel": _FuzzSpec(
        platform=PlatformSpec("ARM_V5T", "LITTLE"),
        pc_register="pc",
        arg_register="r0",
        result_register="r0",
        exit_offset=92,
        engine="unicorn",
    ),
    "armhf": _FuzzSpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pc_register="pc",
        arg_register="r0",
        result_register="r0",
        exit_offset=92,
        engine="unicorn",
    ),
    "m68k": _FuzzSpec(
        platform=PlatformSpec("M68K", "BIG"),
        pc_register="pc",
        result_register="d0",
        exit_offset=0x5C,
        engine="unicorn",
        heap_base=0x3000,
        stack_base=0x4000,
        stack_size=0x4000,
        fake_return=0xFFFF,
    ),
    "m68k.pcode": _FuzzSpec(
        platform=PlatformSpec("M68K", "BIG"),
        pc_register="pc",
        result_register="d0",
        exit_offset=0x5C,
        engine="pcode",
        heap_base=0x3000,
        stack_base=0x4000,
        stack_size=0x4000,
        fake_return=0xFFFF,
    ),
    "mips": _FuzzSpec(
        platform=PlatformSpec("MIPS32", "BIG"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        exit_offset=128,
        engine="unicorn",
    ),
    "mipsel": _FuzzSpec(
        platform=PlatformSpec("MIPS32", "LITTLE"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        exit_offset=128,
        engine="unicorn",
    ),
}

_AFL_SPECS = {
    "aarch64": _FuzzSpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        pc_register="pc",
        arg_register="x0",
        result_register="x1",
        exit_offset=92,
        engine="unicorn",
        heap_size=0x4000,
    ),
    "amd64": _FuzzSpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pc_register="rip",
        arg_register="rdi",
        result_register="eax",
        exit_offset=55,
        engine="unicorn",
        heap_size=0x4000,
    ),
    "armel": _FuzzSpec(
        platform=PlatformSpec("ARM_V5T", "LITTLE"),
        pc_register="pc",
        arg_register="r0",
        result_register="r0",
        exit_offset=92,
        engine="unicorn",
        heap_size=0x4000,
    ),
    "armhf": _FuzzSpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pc_register="pc",
        arg_register="r0",
        result_register="r0",
        exit_offset=92,
        engine="unicorn",
        heap_size=0x4000,
        binary_name="fuzz.armel.bin",
    ),
    "m68k": _FuzzSpec(
        platform=PlatformSpec("M68K", "BIG"),
        pc_register="pc",
        result_register="d0",
        exit_offset=0x5C,
        engine="unicorn",
        heap_size=0x4000,
        stack_base=0x8000,
        stack_size=0x4000,
        fake_return=0xFFFF,
    ),
    "mips": _FuzzSpec(
        platform=PlatformSpec("MIPS32", "BIG"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        exit_offset=128,
        engine="unicorn",
        heap_size=0x4000,
    ),
    "mipsel": _FuzzSpec(
        platform=PlatformSpec("MIPS32", "LITTLE"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        exit_offset=128,
        engine="unicorn",
        heap_size=0x4000,
    ),
}


def can_run(scenario: str, variant: str) -> bool:
    if scenario == "fuzz":
        return variant in _SIMPLE_SPECS
    if scenario == "fuzz.afl_fuzz":
        return variant in _AFL_SPECS
    return False


def _load_code(smallworld, spec: _FuzzSpec, variant: str):
    if spec.binary_name is not None:
        path = TestsPath / "fuzz" / spec.binary_name
    else:
        arch = variant.split(".", 1)[0]
        path = TestsPath / "fuzz" / f"fuzz.{arch}.bin"
    return smallworld.state.memory.code.Executable.from_filepath(path.as_posix(), address=0x1000)


def _configure_argument(smallworld, machine, cpu, platform, spec: _FuzzSpec, size_addr: int) -> None:
    if spec.arg_register is not None:
        getattr(cpu, spec.arg_register).set_content(size_addr)
        return

    stack = smallworld.state.memory.stack.Stack.for_platform(
        platform, spec.stack_base, spec.stack_size
    )
    machine.add(stack)
    stack.push_integer(size_addr, spec.argument_size, None)
    stack.push_integer(spec.fake_return, spec.argument_size, "Fake return")
    cpu.sp.set_content(stack.get_pointer())


def _print_result(final_cpu, spec: _FuzzSpec) -> None:
    value = getattr(final_cpu, spec.result_register)
    if spec.print_raw_value:
        print(value.get())
    else:
        print(value)


def _run_simple(variant: str, args: Sequence[str]) -> int:
    import smallworld

    parser = argparse.ArgumentParser(prog=f"run_case.py fuzz {variant}")
    parser.add_argument(
        "-c", "--crash", default=False, action="store_true", help="use crashing input"
    )
    ns = parser.parse_args(list(args))

    spec = _SIMPLE_SPECS[variant]
    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    code = _load_code(smallworld, spec, variant)
    heap = smallworld.state.memory.heap.BumpAllocator(spec.heap_base, spec.heap_size)

    user_input = b"bad!AAAAAAAA" if ns.crash else b"goodgoodgood"
    size_addr = heap.allocate_integer(
        len(user_input), 4, "user input size", smallworld.platforms.Byteorder[spec.platform.byteorder]
    )
    heap.allocate_bytes(user_input, "user input")

    getattr(cpu, spec.pc_register).set_content(0x1000)
    _configure_argument(smallworld, machine, cpu, platform, spec, size_addr)

    machine.add(heap)
    machine.add(cpu)
    machine.add(code)

    try:
        emulator = make_emulator(smallworld, platform, spec.engine)
        emulator.add_exit_point(0x1000 + spec.exit_offset)
        final_machine = machine.emulate(emulator)
        _print_result(final_machine.get_cpu(), spec)
    except smallworld.exceptions.EmulationError as error:
        print(error)
    return 0


def _run_afl(variant: str, args: Sequence[str]) -> int:
    import smallworld

    spec = _AFL_SPECS[variant]
    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    code = _load_code(smallworld, spec, variant)
    heap = smallworld.state.memory.heap.BumpAllocator(spec.heap_base, spec.heap_size)

    user_input = b"goodgoodgood"
    size_addr = heap.allocate_integer(
        len(user_input), 4, "user input size", smallworld.platforms.Byteorder[spec.platform.byteorder]
    )
    heap.allocate_bytes(user_input, "user input")

    getattr(cpu, spec.pc_register).set_content(0x1000)
    _configure_argument(smallworld, machine, cpu, platform, spec, size_addr)

    machine.add(heap)
    machine.add(cpu)
    machine.add(code)

    def input_callback(uc, input_bytes, persistent_round, data):
        if len(input_bytes) > 0x1000:
            return False
        uc.mem_write(size_addr, input_bytes)
        return None

    emulator = make_emulator(smallworld, platform, spec.engine)
    emulator.add_exit_point(0x1000 + spec.exit_offset)
    machine.fuzz(emulator, input_callback)
    return 0


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if scenario == "fuzz":
        return _run_simple(variant, args)
    if scenario == "fuzz.afl_fuzz":
        return _run_afl(variant, args)
    raise SystemExit(f"unsupported fuzz scenario: {scenario}")
