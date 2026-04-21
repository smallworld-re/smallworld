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

EXPECTED_RESULT = 42
FAKE_EXITPOINT = 0x10101010


@dataclasses.dataclass(frozen=True)
class ExitpointSpec:
    platform: PlatformSpec
    pc_register: str
    result_register: str
    engines: tuple[str, ...]
    mid_exit_offset: int
    load_address: int | None = None
    stack_pointer_register: str = "sp"
    fake_return_size: int | None = 8
    link_register: str | None = None
    entrypoint_registers: tuple[str, ...] = ()
    zero_register_overrides: dict[str, tuple[str, ...]] = dataclasses.field(
        default_factory=dict
    )
    mid_exit_offset_overrides: dict[str, int] = dataclasses.field(default_factory=dict)


_SPECS = {
    "aarch64": ExitpointSpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        pc_register="pc",
        result_register="x0",
        engines=("unicorn", "angr", "pcode"),
        mid_exit_offset=4,
        load_address=0x400000,
        link_register="lr",
    ),
    "amd64": ExitpointSpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pc_register="rip",
        result_register="rax",
        engines=("unicorn", "angr", "pcode"),
        mid_exit_offset=1,
        load_address=0x400000,
        stack_pointer_register="rsp",
    ),
    "armel": ExitpointSpec(
        platform=PlatformSpec("ARM_V6M", "LITTLE"),
        pc_register="pc",
        result_register="r0",
        engines=("unicorn", "angr", "pcode"),
        mid_exit_offset=12,
        link_register="lr",
    ),
    "armhf": ExitpointSpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pc_register="pc",
        result_register="r0",
        engines=("unicorn", "angr", "pcode"),
        mid_exit_offset=12,
        load_address=0x4000000,
        link_register="lr",
    ),
    "i386": ExitpointSpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        pc_register="eip",
        result_register="eax",
        engines=("unicorn", "angr", "pcode"),
        mid_exit_offset=1,
        load_address=0x400000,
        stack_pointer_register="esp",
        fake_return_size=4,
    ),
    "la64": ExitpointSpec(
        platform=PlatformSpec("LOONGARCH64", "LITTLE"),
        pc_register="pc",
        result_register="a0",
        engines=("angr", "pcode"),
        mid_exit_offset=4,
        link_register="ra",
    ),
    "m68k": ExitpointSpec(
        platform=PlatformSpec("M68K", "BIG"),
        pc_register="pc",
        result_register="d0",
        engines=("unicorn", "pcode"),
        mid_exit_offset=4,
        load_address=0x8000000,
        fake_return_size=4,
    ),
    "mips": ExitpointSpec(
        platform=PlatformSpec("MIPS32", "BIG"),
        pc_register="pc",
        result_register="v0",
        engines=("unicorn", "angr", "pcode"),
        mid_exit_offset=8,
        link_register="ra",
        entrypoint_registers=("t9",),
    ),
    "mipsel": ExitpointSpec(
        platform=PlatformSpec("MIPS32", "LITTLE"),
        pc_register="pc",
        result_register="v0",
        engines=("unicorn", "angr", "pcode"),
        mid_exit_offset=8,
        link_register="ra",
        entrypoint_registers=("t9",),
    ),
    "mips64": ExitpointSpec(
        platform=PlatformSpec("MIPS64", "BIG"),
        pc_register="pc",
        result_register="v0",
        engines=("unicorn", "angr", "pcode"),
        mid_exit_offset=8,
        fake_return_size=None,
        link_register="ra",
        entrypoint_registers=("t9",),
    ),
    "mips64el": ExitpointSpec(
        platform=PlatformSpec("MIPS64", "LITTLE"),
        pc_register="pc",
        result_register="v0",
        engines=("unicorn", "angr", "pcode"),
        mid_exit_offset=8,
        fake_return_size=None,
        link_register="ra",
        entrypoint_registers=("t9",),
    ),
    "ppc": ExitpointSpec(
        platform=PlatformSpec("POWERPC32", "BIG"),
        pc_register="pc",
        result_register="r3",
        engines=("unicorn", "angr", "pcode"),
        mid_exit_offset=4,
        link_register="lr",
    ),
    "ppc64": ExitpointSpec(
        platform=PlatformSpec("POWERPC64", "BIG"),
        pc_register="pc",
        result_register="r3",
        engines=("angr", "pcode"),
        mid_exit_offset=16,
        load_address=0x400000,
        link_register="lr",
        zero_register_overrides={"angr": ("r12",)},
        mid_exit_offset_overrides={"angr": 20},
    ),
    "riscv64": ExitpointSpec(
        platform=PlatformSpec("RISCV64", "LITTLE"),
        pc_register="pc",
        result_register="a0",
        engines=("unicorn", "angr", "pcode"),
        mid_exit_offset=4,
        load_address=0x400000,
        link_register="ra",
    ),
    "tricore": ExitpointSpec(
        platform=PlatformSpec("TRICORE", "LITTLE"),
        pc_register="pc",
        result_register="d2",
        engines=("angr", "pcode"),
        mid_exit_offset=2,
        fake_return_size=4,
        link_register="ra",
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
    if scenario != "exitpoint":
        return False
    if variant in _SKIP_REASONS:
        return True
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def _build_machine(smallworld, arch: str, engine: str, spec: ExitpointSpec):
    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_elf_code(
        smallworld,
        "exitpoint",
        arch,
        platform,
        address=spec.load_address,
    )
    machine.add(code)

    entrypoint = code.get_symbol_value("main")
    set_register(cpu, spec.pc_register, entrypoint)
    for register_name in spec.entrypoint_registers:
        set_register(cpu, register_name, entrypoint)

    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
    machine.add(stack)
    if spec.fake_return_size is not None:
        stack.push_integer(FAKE_EXITPOINT, spec.fake_return_size, None)
    set_register(cpu, spec.stack_pointer_register, stack.get_pointer())

    if spec.link_register is not None:
        set_register(cpu, spec.link_register, FAKE_EXITPOINT)
    for register_name in spec.zero_register_overrides.get(engine, ()):
        set_register(cpu, register_name, 0)

    for start, end in code.bounds:
        machine.add_bound(start, end)

    return machine, platform, code, entrypoint


def _run_exit_test(
    smallworld, arch: str, engine: str, spec: ExitpointSpec, exitpoint: int
) -> None:
    machine, platform, _, _ = _build_machine(smallworld, arch, engine, spec)
    machine.add_exit_point(exitpoint)

    emulator = make_emulator(smallworld, platform, engine)
    maybe_enable_linear(smallworld, emulator, engine)

    final_cpu = machine.emulate(emulator).get_cpu()
    if final_cpu.pc.get() != exitpoint:
        raise ValueError(f"Expected PC to be {hex(exitpoint)}, got {final_cpu.pc}")

    result = getattr(final_cpu, spec.result_register).get()
    if result != EXPECTED_RESULT:
        raise ValueError(
            f"Expected {spec.result_register} to be {EXPECTED_RESULT:#x}, "
            f"got {result:#x}"
        )


def _mid_exitpoint(entrypoint: int, code, engine: str, spec: ExitpointSpec) -> int:
    return (
        entrypoint
        + code.get_symbol_size("main")
        - spec.mid_exit_offset_overrides.get(engine, spec.mid_exit_offset)
    )


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if args:
        raise SystemExit(f"{scenario} does not take extra arguments: {' '.join(args)}")
    if variant in _SKIP_REASONS:
        raise SystemExit(_SKIP_REASONS[variant])

    import smallworld

    arch, engine = split_variant(variant)
    spec = _SPECS[arch]

    smallworld.logging.setup_logging(level=logging.INFO)

    _run_exit_test(smallworld, arch, engine, spec, FAKE_EXITPOINT)
    print("Test 1 SUCCESS")

    _, _, code, entrypoint = _build_machine(smallworld, arch, engine, spec)
    mid_exitpoint = _mid_exitpoint(entrypoint, code, engine, spec)
    _run_exit_test(smallworld, arch, engine, spec, mid_exitpoint)
    print("Test 2 SUCCESS")
    return 0
