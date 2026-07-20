from __future__ import annotations

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
from .spec import ScenarioInfo, from_arch_table, just_run

NATIVE_PARITY = False


@dataclasses.dataclass(frozen=True)
class NullPcSpec:
    # Architectural facts needed to load a raw blob and run it to the point
    # where it computes a jump to address 0. Populated from ARCH_REGISTERS via
    # build_specs(); see common.ARCH_REGISTERS for the per-arch values.
    platform: PlatformSpec
    pc_register: str
    engines: tuple[str, ...]
    stack_pointer_register: str
    entry_offset: int = 0
    # A synthetic return address left on the stack. It is deliberately non-zero
    # so that, for the return-based programs (i386/tricore/xtensa), only the
    # test's own zeroing of the return target -- not a leftover 0 on the stack
    # -- can send control to NULL.
    fake_return: int = 0xFFFFFFFF
    fake_return_size: int = 8
    stack_padding_bytes: int = 0


# Every architecture whose null_pc.<arch>.bin computes a jump to address 0.
# msp430 is intentionally excluded (its binary does not do what we want).
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

_SPECS = build_specs(NullPcSpec, _ARCHS)

# ppc64 uses angr/pcode only: unicorn's ppc64 support is buggy (matches the
# branch/unmapped scenarios). PANDA is a supported engine for several arches
# but is mid-migration and not yet runnable, so its variants are skipped just
# as they are in the unmapped scenario.
_SKIP_REASONS = {
    "ppc64": "Unicorn ppc64 support buggy",
    "aarch64.panda": "Waiting for panda-ng",
    "amd64.panda": "Waiting for panda-ng",
    "armel.panda": "Waiting for panda-ng",
    "armhf.panda": "Waiting for panda-ng",
    "i386.panda": "Waiting for panda-ng",
    "mips.panda": "Waiting for panda-ng",
    "mipsel.panda": "Waiting for panda-ng",
    "mips64.panda": "Waiting for panda-ng",
    "mips64el.panda": "Waiting for panda-ng",
    "ppc.panda": "Waiting for panda-ng",
    "tricore.panda": "Waiting for panda-ng",
}


SCENARIO_PREFIXES = (("null_pc", "null_pc"),)

SCENARIO_INFO = ScenarioInfo(
    prefix="null_pc",
    scenario="null_pc",
    tags=("scenario", "null_pc"),
    variants_source=from_arch_table(_SPECS, skip_reasons=_SKIP_REASONS),
    run_factory=just_run(),
)


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "null_pc":
        return False
    if variant in _SKIP_REASONS:
        return True
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if variant in _SKIP_REASONS:
        raise SystemExit(_SKIP_REASONS[variant])
    if args:
        raise SystemExit(f"{scenario} does not take arguments: {' '.join(args)}")

    import smallworld

    arch, engine = split_variant(variant)
    spec = _SPECS[arch]

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, "null_pc", arch)
    machine.add(code)
    set_register(cpu, spec.pc_register, code.address + spec.entry_offset)

    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
    machine.add(stack)
    if spec.stack_padding_bytes:
        # PowerPC keeps ABI scratch data above SP; reserve it first if needed.
        stack.push_bytes(b"\0" * spec.stack_padding_bytes, None)
    stack.push_integer(spec.fake_return, spec.fake_return_size, "fake return address")
    set_register(cpu, spec.stack_pointer_register, stack.get_pointer())

    emulator = make_emulator(smallworld, platform, engine)
    if engine == "angr" and isinstance(emulator, smallworld.emulators.AngrEmulator):
        emulator.error_on_unmapped = True

    # A non-zero exit point just past the code: it satisfies the emulator's
    # "need an exit point or bound" check without reserving address 0, so a jump
    # to NULL is reported as a fetch fault rather than mistaken for a clean exit.
    emulator.add_exit_point(code.address + code.get_capacity())

    try:
        machine.emulate(emulator)
    except smallworld.exceptions.EmulationFetchUnmappedFailure:
        return 0
    raise RuntimeError("Did not report jump to NULL (address 0)")
