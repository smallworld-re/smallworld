"""Intel 8051 scenarios.

``mcs51_spaces``: the 8051 keeps code, external RAM (XDATA), internal RAM and
the special function registers (SFRs) in separate address spaces.  SmallWorld
lays them out side by side in one flat map (``smallworld.platforms.defs.mcs51``),
and the Ghidra backend translates every access to the matching Ghidra space.
This scenario touches each space through each instruction form that reaches it -
direct, indirect, ``movx``, ``movc``, and the memory-to-memory ``mov dir,dir``
that Ghidra expresses as a single COPY between two memory varnodes - and checks
both where the bytes landed and the flat address a memory hook reports.  It also
covers ``da a``, which Ghidra leaves to the host as a user-defined operation.

``mcs51_flags``: what Ghidra's stock 8051 language gets wrong and
``nix/patches/ghidra-8051.patch`` fixes - the carry out of ``addc``/``subb``
with an operand of 0xFF, the auxiliary carry and overflow flags, PSW's user
flag F0 surviving arithmetic, bit instructions acting on the bits of internal
RAM and of register-backed SFRs, and ``mov sp,#n``.  Run against an unpatched
Ghidra, it fails, which makes it the check that the patched language loaded: if
it starts failing, suspect first that Ghidra loaded its stock 8051 language
(see ``nix/ghidra.nix``), and check which ``8051.sla`` Ghidra reports with
``language.getLanguageDescription().getSlaFile()``.

Still not modeled: register banks (R0-R7 are standalone registers, not internal
RAM 0x00-0x1F selected by PSW's RS bits).
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Callable, Dict, Sequence, Tuple

from .common import load_raw_code, make_emulator, split_variant
from .spec import ScenarioInfo, from_variants, just_run

NATIVE_PARITY = True

_VARIANTS = ("mcs51.angr", "mcs51.pcode")

SCENARIO_INFOS = tuple(
    ScenarioInfo(
        prefix=name,
        scenario=name,
        tags=("scenario", name),
        variants_source=from_variants(tuple((v, None) for v in _VARIANTS)),
        run_factory=just_run(),
    )
    for name in ("mcs51_spaces", "mcs51_flags")
)


def can_run(scenario: str, variant: str) -> bool:
    return scenario in ("mcs51_spaces", "mcs51_flags") and variant in _VARIANTS


def _run(
    scenario: str,
    variant: str,
    setup: Callable[[Any, Any], None],
    checks: Callable[[Any, Any], Dict[str, Tuple[Any, Any]]],
) -> int:
    import smallworld
    from smallworld.platforms.defs.mcs51 import (
        MCS51_IDATA_BASE,
        MCS51_SFR_BASE,
        MCS51_XDATA_BASE,
    )

    arch, engine = split_variant(variant)
    smallworld.logging.setup_logging(level=logging.INFO)

    platform = smallworld.platforms.Platform(
        smallworld.platforms.Architecture.MCS51, smallworld.platforms.Byteorder.BIG
    )
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, scenario, arch)
    machine.add(code)
    cpu.pc.set(code.address)
    cpu.sp.set(0x07)
    # The 8051 resets PSW and the accumulator to zero.  Set them, so angr
    # does not treat the bits the program reads back as unconstrained.
    cpu.psw.set(0)
    cpu.acc.set(0)

    for base, size in (
        (MCS51_IDATA_BASE, 0x100),
        (MCS51_XDATA_BASE, 0x10000),
        (MCS51_SFR_BASE, 0x100),
    ):
        machine.add(smallworld.state.memory.RawMemory.from_bytes(b"\0" * size, base))

    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(code.address + code.get_capacity())
    setup(cpu, emulator)

    final_cpu = machine.emulate(emulator).get_cpu()

    def show(value) -> str:
        return hex(value) if isinstance(value, int) else repr(value)

    failed = False
    for name, (actual, expected) in checks(final_cpu, emulator).items():
        status = "ok" if actual == expected else "FAIL"
        failed = failed or actual != expected
        print(f"{status:4} {name}: {show(actual)} (expected {show(expected)})")
    if failed:
        sys.exit(1)
    return 0


def _run_spaces(variant: str) -> int:
    from smallworld.platforms.defs.mcs51 import (
        MCS51_IDATA_BASE,
        MCS51_SFR_BASE,
        MCS51_XDATA_BASE,
    )

    hooked = []

    def setup(cpu, emulator) -> None:
        cpu.sp.set(0x60)
        emulator.hook_memory_write(
            MCS51_IDATA_BASE + 0x30,
            MCS51_IDATA_BASE + 0x31,
            lambda emu, addr, size, data: hooked.append((addr, bytes(data))),
        )

    def checks(cpu, emulator):
        def byte(base: int, offset: int) -> int:
            return emulator.read_memory(base + offset, 1)[0]

        return {
            "idata[0x30] (direct)": (byte(MCS51_IDATA_BASE, 0x30), 0x5A),
            "idata[0x40] (indirect)": (byte(MCS51_IDATA_BASE, 0x40), 0x11),
            "idata[0x31] (mov dir,dir)": (byte(MCS51_IDATA_BASE, 0x31), 0x5A),
            "idata[0x61] (push)": (byte(MCS51_IDATA_BASE, 0x61), 0x11),
            "xdata[0x1234] (movx)": (byte(MCS51_XDATA_BASE, 0x1234), 0x22),
            "sfr[0x90] (P1)": (byte(MCS51_SFR_BASE, 0x90), 0x77),
            "sfr[0x80] (P0 = P1)": (byte(MCS51_SFR_BASE, 0x80), 0x77),
            "r1 (mov a,dir)": (cpu.r1.get(), 0x5A),
            "r2 (movc)": (cpu.r2.get(), 0xC3),
            "r3 (da a)": (cpu.r3.get(), 0x42),
            "r4 (movx read)": (cpu.r4.get(), 0x22),
            "r5 (mov a,@r0)": (cpu.r5.get(), 0x11),
            "b (pop)": (cpu.b.get(), 0x11),
            "sp": (cpu.sp.get(), 0x60),
            "write hook": (hooked, [(MCS51_IDATA_BASE + 0x30, b"\x5a")]),
        }

    return _run("mcs51_spaces", variant, lambda cpu, emu: setup(cpu, emu), checks)


# PSW bits: CY 0x80, AC 0x40, F0 0x20, OV 0x04, P 0x01 (parity of A).
def _run_flags(variant: str) -> int:
    from smallworld.platforms.defs.mcs51 import MCS51_IDATA_BASE

    def checks(cpu, emulator):
        def idata(offset: int) -> int:
            return emulator.read_memory(MCS51_IDATA_BASE + offset, 1)[0]

        return {
            "sp (mov sp,#0x50 then push)": (cpu.sp.get(), 0x51),
            "idata[0x51] (push)": (idata(0x51), 0x47),
            "idata[0x20] (setb 0x03)": (idata(0x20), 0x08),
            "r7 (setb ACC.7)": (cpu.r7.get(), 0x80),
            "r6 (psw after 0xFF + 1)": (cpu.r6.get(), 0xC0),
            "r5 (psw after 1 + 0xFF + CY)": (cpu.r5.get(), 0xC1),
            "r4 (1 + 0xFF + CY)": (cpu.r4.get(), 0x01),
            "r3 (0x10 - 0xFF - CY)": (cpu.r3.get(), 0x10),
            "r2 (psw after 0x10 - 0xFF - CY)": (cpu.r2.get(), 0xC1),
            "r1 (psw after 0x7F + 1, F0 set)": (cpu.r1.get(), 0x65),
            "r0 (da a after 19 + 28)": (cpu.r0.get(), 0x47),
        }

    return _run("mcs51_flags", variant, lambda cpu, emu: None, checks)


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if scenario == "mcs51_spaces":
        return _run_spaces(variant)
    return _run_flags(variant)
