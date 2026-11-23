"""The 8051 against an independent simulator, ucsim_51.

Each program in ``tests/mcs51_diff`` runs from a random starting state, and
``tests/mcs51_diff/generate.py`` records where ucsim_51 - SDCC's 8051
simulator, run as an 8052 - says it ends, in ``<program>.json``.  This scenario
loads the same starting state into SmallWorld, runs the program, and compares:

* A, B, SP, DPTR and PSW;
* R0-R7, against the register bank the final PSW selects;
* all of internal RAM, register banks included;
* every SFR that SmallWorld does not model as a register;
* XDATA 0x0000-0x00FF.

ucsim is not hardware: a difference here needs checking against the 8051
manual before it is called a SmallWorld bug.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Sequence

from .common import TestsPath, make_emulator, split_variant
from .spec import ScenarioInfo, from_variants, just_run

NATIVE_PARITY = True

_DIR = TestsPath / "mcs51_diff"
_PROGRAMS = tuple(sorted(path.stem for path in _DIR.glob("*.json")))
_VARIANTS = ("mcs51.angr", "mcs51.pcode")

# SFRs that SmallWorld models as registers rather than SFR memory.
_REGISTER_SFRS = {
    0x81: "sp",
    0x82: "dpl",
    0x83: "dph",
    0xD0: "psw",
    0xE0: "acc",
    0xF0: "b",
}

SCENARIO_INFOS = tuple(
    ScenarioInfo(
        prefix=f"mcs51_diff.{program}",
        scenario=f"mcs51_diff.{program}",
        tags=("scenario", "mcs51_diff"),
        variants_source=from_variants(tuple((v, None) for v in _VARIANTS)),
        run_factory=just_run(),
    )
    for program in _PROGRAMS
)


def can_run(scenario: str, variant: str) -> bool:
    return (
        scenario.startswith("mcs51_diff.")
        and scenario.split(".", 1)[1] in _PROGRAMS
        and variant in _VARIANTS
    )


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    import smallworld
    from smallworld.platforms.defs.mcs51 import (
        MCS51_IDATA_BASE,
        MCS51_SFR_BASE,
        MCS51_XDATA_BASE,
    )

    program = scenario.split(".", 1)[1]
    arch, engine = split_variant(variant)
    expected = json.loads((_DIR / f"{program}.json").read_text())
    initial = {key: bytes.fromhex(value) for key, value in expected["initial"].items()}
    final = {key: bytes.fromhex(value) for key, value in expected["final"].items()}

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = smallworld.platforms.Platform(
        smallworld.platforms.Architecture.MCS51, smallworld.platforms.Byteorder.BIG
    )
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    # The binary starts below the program's code when it fills interrupt
    # vectors; older results predate load_address.
    code = smallworld.state.memory.code.Executable.from_filepath(
        (_DIR / f"{program}.{arch}.bin").as_posix(),
        address=expected.get("load_address", expected["code_base"]),
    )
    machine.add(code)
    cpu.pc.set(expected["code_base"])

    def sfr(memory: bytes, address: int) -> int:
        return memory[address - 0x80]

    for address, register in _REGISTER_SFRS.items():
        if register not in ("dpl", "dph"):
            getattr(cpu, register).set(sfr(initial["sfr"], address))
    cpu.dptr.set((sfr(initial["sfr"], 0x83) << 8) | sfr(initial["sfr"], 0x82))
    bank = (sfr(initial["sfr"], 0xD0) >> 3) & 3
    for i in range(8):
        getattr(cpu, f"r{i}").set(initial["iram"][bank * 8 + i])

    xdata = initial["xdata"] + b"\0" * (0x10000 - len(initial["xdata"]))
    for base, content in (
        (MCS51_IDATA_BASE, initial["iram"]),
        (MCS51_SFR_BASE + 0x80, initial["sfr"]),
        (MCS51_XDATA_BASE, xdata),
    ):
        machine.add(smallworld.state.memory.RawMemory.from_bytes(content, base))

    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(code.address + code.get_capacity())
    final_cpu = machine.emulate(emulator).get_cpu()

    mismatches = []

    def compare(what: str, actual: int, wanted: int) -> None:
        if actual != wanted:
            mismatches.append(f"{what}: {actual:#04x}, ucsim {wanted:#04x}")

    for address, register in _REGISTER_SFRS.items():
        wanted = sfr(final["sfr"], address)
        actual = getattr(final_cpu, register).get()
        compare(register, actual, wanted)
    bank = (sfr(final["sfr"], 0xD0) >> 3) & 3
    for i in range(8):
        compare(
            f"r{i} (bank {bank})",
            getattr(final_cpu, f"r{i}").get(),
            final["iram"][bank * 8 + i],
        )

    iram = emulator.read_memory(MCS51_IDATA_BASE, 0x100)
    for address in range(0x00, 0x100):
        compare(f"iram[{address:#04x}]", iram[address], final["iram"][address])
    sfrs = emulator.read_memory(MCS51_SFR_BASE + 0x80, 0x80)
    for address in range(0x80, 0x100):
        if address not in _REGISTER_SFRS:
            compare(
                f"sfr[{address:#04x}]", sfrs[address - 0x80], sfr(final["sfr"], address)
            )
    xram = emulator.read_memory(MCS51_XDATA_BASE, len(final["xdata"]))
    for address, wanted in enumerate(final["xdata"]):
        compare(f"xdata[{address:#06x}]", xram[address], wanted)

    for mismatch in mismatches:
        print(f"MISMATCH {mismatch}")
    if mismatches:
        print(f"{program}: {len(mismatches)} differences from ucsim_51")
        sys.exit(1)
    print(f"{program}: matches ucsim_51")
    return 0
