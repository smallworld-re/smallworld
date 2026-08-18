from __future__ import annotations

import logging
from typing import Sequence

from .common import (
    build_specs,
    load_raw_code,
    make_emulator,
    make_platform,
    set_register,
    split_variant,
)
from .raw_binary import RawBinarySpec
from .spec import ScenarioInfo, from_arch_table, just_run

NATIVE_PARITY = True

_ARCHS = (
    "aarch64",
    "amd64",
    "armel",
    "armhf",
    "i386",
    "m68k",
    "mips",
    "mipsel",
    "ppc",
    "sh2a",
    "sh4",
    "sh4el",
)

_ENGINES_UNICORN_PANDA = ("unicorn", "panda")

# SuperH has no unicorn backend, so panda is the only engine here, and it works:
# QEMU's `helper_trapa()` sets `cs->exception_index = 0x160` unconditionally,
# which reaches PANDA's `cb_before_handle_exception` and so `hook_interrupts`,
# which sees interrupt 352 on all three SuperH variants.
#
# The other three engines are excluded, and for two different reasons:
#
#   * angr, pcode - `hook_interrupts` does not exist on those emulator classes.
#     Only `QInterruptHookable` provides it, and `AngrEmulator` mixes in
#     `SyscallHookable` but not `InterruptHookable`, while `GhidraEmulator` mixes
#     in neither.  Measured, `hasattr(cls, "hook_interrupts")`: AngrEmulator
#     False, GhidraEmulator False, PandaEmulator True, StyxEmulator True,
#     UnicornEmulator True.  On angr this is not merely a gap: `trapa` is
#     deliberately surfaced there as a *syscall* instead, by the rewrite in
#     `smallworld/emulators/angr/machdefs/superh{,4}.py`, which is what the
#     `syscall` scenario covers.  So the same instruction is an interrupt here
#     and a syscall there - see the long comment in `machdefs/superh.py`.
#   * styx - does implement `hook_interrupts` (it mixes in
#     `QInterruptHookable`), so it was a real candidate, but SuperH `trapa` never
#     reaches it.  Measured on sh2a: `trapa` writes to the stack - with no stack
#     mapped it fails with UnmappedMemoryWrite - and then falls through to the
#     next instruction instead of vectoring through VBR, raising nothing.  Ghidra
#     on the identical sleigh semantics instead faults on the vector read, so
#     Styx is the one that is wrong here.
_ENGINES_PANDA = ("panda",)

_SPECS = build_specs(
    RawBinarySpec,
    _ARCHS,
    engines={
        "aarch64": _ENGINES_UNICORN_PANDA,
        "amd64": _ENGINES_UNICORN_PANDA,
        "armel": _ENGINES_UNICORN_PANDA,
        "armhf": _ENGINES_UNICORN_PANDA,
        "i386": _ENGINES_UNICORN_PANDA,
        "m68k": ("unicorn",),
        "mips": _ENGINES_UNICORN_PANDA,
        "mipsel": _ENGINES_UNICORN_PANDA,
        "ppc": _ENGINES_UNICORN_PANDA,
        "sh2a": _ENGINES_PANDA,
        "sh4": _ENGINES_PANDA,
        "sh4el": _ENGINES_PANDA,
    },
    # interrupt reads the full-width return register on amd64.
    per_arch={"amd64": {"result_register": "rax"}},
)


SCENARIO_PREFIXES = (("interrupt", "interrupt"),)

SCENARIO_INFO = ScenarioInfo(
    prefix="interrupt",
    scenario="interrupt",
    tags=("scenario", "interrupt"),
    variants_source=from_arch_table(
        _SPECS,
        skip_reasons={
            "amd64": "Interrupt hook doesn't fire",
            "i386": "Interrupt hook doesn't fire",
        },
    ),
    run_factory=just_run(),
)


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "interrupt":
        return False
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    import smallworld

    arch, engine = split_variant(variant)

    spec = _SPECS[arch]

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, "interrupt", arch)
    machine.add(code)
    set_register(cpu, spec.pc_register, code.address)
    emulator = make_emulator(smallworld, platform, engine)

    exit_point = code.address + code.get_capacity()
    machine.add_exit_point(exit_point)

    def interrupt_hook(emu: smallworld.emulators.Emulator, intno: int) -> bool:
        print(f"Received interrupt {intno}")
        raise smallworld.exceptions.EmulationStop()

    emulator.hook_interrupts(interrupt_hook)

    machine.emulate(emulator)

    return 0
