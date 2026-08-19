from __future__ import annotations

import argparse
import dataclasses
import logging
from typing import Sequence

from .common import (
    PlatformSpec,
    enroll_triton,
    load_elf_code,
    make_emulator,
    make_platform,
    run_case_subprocess,
    set_register,
    split_variant,
)
from .spec import ScenarioInfo, from_arch_table, just_run

NATIVE_PARITY = True


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
    # SuperH has no C compiler in this tree, so unmapped.sh{2a,4}.elf.s stand in
    # for unmapped.elf.c the way unmapped.tricore.elf.s does.  All three SuperH
    # variants are ET_EXEC with a single PT_LOAD at 0x400000 (measured with
    # sh4-unknown-linux-gnu-readelf -l), so load_address stays None and the
    # loader honours the file's own addresses; the faulting address is 0x8000,
    # the same one the C version uses, which sits above the harness's
    # 0x2000..0x6000 stack and below the image.  No stack padding and no
    # entrypoint register: SuperH takes its return address from `pr`, which
    # these functions never need because nothing returns.
    #
    # styx is absent deliberately - see _SKIP_REASONS.
    "sh2a": UnmappedSpec(
        platform=PlatformSpec("SUPERH_SH2A_FPU", "BIG"),
        pc_register="pc",
        engines=("angr", "pcode", "panda"),
    ),
    "sh4": UnmappedSpec(
        platform=PlatformSpec("SUPERH_SH4", "BIG"),
        pc_register="pc",
        engines=("angr", "pcode", "panda"),
    ),
    "sh4el": UnmappedSpec(
        platform=PlatformSpec("SUPERH_SH4", "LITTLE"),
        pc_register="pc",
        engines=("angr", "pcode", "panda"),
    ),
    "tricore": UnmappedSpec(
        platform=PlatformSpec("TRICORE", "LITTLE"),
        pc_register="pc",
        engines=("angr", "panda", "pcode"),
    ),
}

# Triton emulates x86, x86-64, ARM32, AArch64 and RISC-V; enroll it on those.
_SPECS = enroll_triton(_SPECS)

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
    # Measured: Styx's SuperH2A target maps a flat 4 GiB RWX space, so none of
    # the three accesses can fault.  Single-stepping unmapped.sh2a.elf's
    # read_unmapped shows `mov.l @r1,r0` with r1=0x8000 completing and yielding
    # 0 (and StyxEmulator.read_memory(0x8000, 4) returning zeroes) even though
    # get_memory_map() reports only 0x2000-0x6000 and 0x400000-0x401000; the run
    # then falls through `rts` into address 0 and dies with an unrelated
    # InstructionDecodeError.  sh2a is the only ARCH_REGISTERS row listing styx.
    "sh2a.styx": "styx SuperH2A maps a flat 4 GiB space, "
    "so an unmapped access cannot fault",
}


SCENARIO_PREFIXES = (("unmapped", "unmapped"),)

SCENARIO_INFO = ScenarioInfo(
    prefix="unmapped",
    scenario="unmapped",
    tags=("scenario", "unmapped"),
    variants_source=from_arch_table(
        _SPECS,
        extra_variants=tuple(
            (variant, reason, {}) for variant, reason in _SKIP_REASONS.items()
        ),
    ),
    run_factory=just_run(),
)


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

    if engine in ("unicorn", "triton"):
        # Neither backend will start without somewhere to stop: Unicorn needs an
        # exit sentinel and Triton's run loop refuses to run with no exit point
        # or bound. Address 0 is the right sentinel because no return address is
        # pushed, so the function under test returns into the zero-filled stack
        # and lands there; the faults this scenario is about happen earlier, at
        # the unmapped target (0x8000).
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
    if engine == "panda":
        for start, end in code.bounds:
            machine.add_bound(start, end)

    emulator = make_emulator(smallworld, platform, engine)
    if engine == "angr" and isinstance(emulator, smallworld.emulators.AngrEmulator):
        emulator.error_on_unmapped = True

    try:
        machine.emulate(emulator)
    except expected_exception:
        return
    raise RuntimeError(f"Did not report {symbol.replace('_', ' ')}")


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if variant in _SKIP_REASONS:
        raise SystemExit(_SKIP_REASONS[variant])

    import smallworld

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--panda-operation",
        choices=("read_unmapped", "write_unmapped", "fetch_unmapped"),
    )
    ns, extra = parser.parse_known_args(list(args))
    if extra:
        raise SystemExit(f"{scenario} does not take extra arguments: {' '.join(extra)}")

    arch, engine = split_variant(variant)
    spec = _SPECS[arch]

    smallworld.logging.setup_logging(level=logging.DEBUG)

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
    if engine == "panda" and ns.panda_operation is None:
        for symbol, _, label in operations:
            run_case_subprocess(scenario, variant, "--panda-operation", symbol)
            print(f"{label} SUCCESS")
        return 0

    for symbol, expected_exception, label in operations:
        if ns.panda_operation is not None and symbol != ns.panda_operation:
            continue
        _run_operation(smallworld, arch, engine, spec, symbol, expected_exception)
    return 0
