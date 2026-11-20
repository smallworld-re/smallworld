from __future__ import annotations

import argparse
import logging
from typing import Sequence

from .common import ARCH_REGISTERS, make_emulator, make_platform, split_variant
from .spec import ScenarioInfo, assert_outputs, from_variants

NATIVE_PARITY = False

# SmallWorld's V850 model is V850E1/E2/E2M. RH850's (V850E3v5's) additional
# instructions must not run as something else. These two fail to decode, as
# they should; each is assembled by GNU as with -mv850e3v5 and followed by a
# nop. `mov r6, r7` is the control.
#
# Not every RH850 instruction faults: `loop`, `synci`, `ld.dw`, `st.dw`, the
# 17-bit-displacement branches, `dbhvtrap` and `dbcp` reuse encodings that
# V850 decodes as other instructions, and run as those. See the V850 notes in
# docs/concepts/platforms/support.rst.
_PROGRAMS = {
    "rotl": bytes.fromhex("e337c438" "0000"),  # rotl 3, r6, r7
    "pushsp": bytes.fromhex("f44760c9" "0000"),  # pushsp r20-r25
    "mov": bytes.fromhex("0638" "0000"),  # mov r6, r7
}

_R6 = 0x1234

_VARIANTS = tuple((f"v850.{engine}", None) for engine in ("angr", "pcode"))

SCENARIO_PREFIXES = (("v850_isa", "v850_isa"),)

SCENARIO_INFO = ScenarioInfo(
    prefix="v850_isa",
    scenario="v850_isa",
    tags=("scenario", "v850_isa"),
    variants_source=from_variants(_VARIANTS),
    run_factory=assert_outputs(
        lambda variant, kwargs: (
            (("rotl",), "illegal instruction"),
            (("pushsp",), "illegal instruction"),
            (("mov",), f"r7={_R6:#x}"),
        )
    ),
)


def can_run(scenario: str, variant: str) -> bool:
    return scenario == "v850_isa" and variant in dict(_VARIANTS)


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog=f"run_case.py {scenario} {variant}")
    parser.add_argument("program", choices=sorted(_PROGRAMS))
    ns = parser.parse_args(list(args))

    import smallworld

    arch, engine = split_variant(variant)
    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, ARCH_REGISTERS[arch].platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = smallworld.state.memory.code.Executable.from_bytes(
        _PROGRAMS[ns.program], address=0x1000
    )
    machine.add(code)
    cpu.pc.set(code.address)
    cpu.r6.set(_R6)
    cpu.r7.set(0)

    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(code.address + code.get_capacity())
    try:
        final_cpu = machine.emulate(emulator).get_cpu()
    except smallworld.exceptions.EmulationExecInvalidFailure:
        print("illegal instruction")
        return 0
    print(f"r7={final_cpu.r7.get():#x}")
    return 0
