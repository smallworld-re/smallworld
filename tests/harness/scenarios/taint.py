"""Triton taint-tracking scenario.

Taint is a Triton-specific escape hatch rather than part of the SmallWorld
``Emulator`` contract (``taint_register``/``taint_memory``/``is_*_tainted`` are
only defined on :class:`~smallworld.emulators.triton.TritonEmulator`), so this
scenario runs on the ``triton`` engine alone.

``taint/taint.<arch>.s`` is a straight-line program whose only job is to be a
data-flow graph the harness can predict exactly:

    out1  = in0 + 1     register -> register
    slot0 = out1        register -> memory
    out2  = slot0       memory   -> register
    slot1 = in1         a store that never touches a tainted value
    out3  = slot1       a load that never touches a tainted value
    out4  = slot2       a load from a slot the harness seeds itself
    in0   = 0           overwriting with a constant must clear taint

Three families run that program with different taint applied up front:

``propagation``
    Taint ``in0``. Taint must reach ``out1``, ``slot0`` and ``out2`` and nothing
    else — and ``in0`` itself must come back clean, because the program's last
    instruction overwrites it with a constant.
``memory``
    Taint ``slot2`` instead. Only ``out4`` (and ``slot2``) may come back
    tainted, which checks the memory -> register direction on its own.
``isolation``
    Taint ``in0`` and ``slot2``, then untaint both before running. Nothing may
    come back tainted; this is the negative control that would catch a backend
    reporting everything as tainted, and it exercises ``untaint_register`` and
    ``untaint_memory``.

Every family also checks the concrete results, so a run that quietly failed to
execute the program cannot pass its taint assertions by accident.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Sequence

from .common import (
    PlatformSpec,
    load_raw_code,
    make_emulator,
    make_platform,
    set_register,
    split_variant,
)
from .spec import ScenarioInfo, from_arch_table, just_run

NATIVE_PARITY = False

# Where the scenario's scratch slots live. Triton's memory is flat and lazy, but
# the machine still gets a real Memory region so the state is well-formed.
SCRATCH_ADDRESS = 0x3000
SCRATCH_SIZE = 0x100

# Inputs and the value the harness seeds into slot2. Distinct so a mixed-up
# result register is obvious in the failure message.
TAINTED_INPUT = 0x1234
CLEAN_INPUT = 0x5678
SEEDED_SLOT = 0x9ABC


@dataclasses.dataclass(frozen=True)
class TaintSpec:
    platform: PlatformSpec
    pc_register: str
    # (register holding the taintable input, register holding the clean input)
    input_registers: tuple[str, str]
    # (in0 + 1, load of slot0, load of slot1, load of slot2)
    output_registers: tuple[str, str, str, str]
    # Width of one scratch slot, and of the loads and stores in the program.
    word_size: int
    engines: tuple[str, ...] = ("triton",)


_SPECS = {
    "aarch64": TaintSpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        pc_register="pc",
        input_registers=("x0", "x1"),
        output_registers=("x2", "x3", "x4", "x6"),
        word_size=8,
    ),
    "amd64": TaintSpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pc_register="rip",
        input_registers=("rdi", "rsi"),
        output_registers=("rax", "rcx", "rdx", "r8"),
        word_size=8,
    ),
    "armel": TaintSpec(
        platform=PlatformSpec("ARM_V5T", "LITTLE"),
        pc_register="pc",
        input_registers=("r0", "r1"),
        output_registers=("r2", "r3", "r4", "r6"),
        word_size=4,
    ),
    "armhf": TaintSpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pc_register="pc",
        input_registers=("r0", "r1"),
        output_registers=("r2", "r3", "r4", "r6"),
        word_size=4,
    ),
    "i386": TaintSpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        pc_register="eip",
        input_registers=("edi", "esi"),
        output_registers=("eax", "ecx", "edx", "ebp"),
        word_size=4,
    ),
    "riscv64": TaintSpec(
        platform=PlatformSpec("RISCV64", "LITTLE"),
        pc_register="pc",
        input_registers=("a0", "a1"),
        output_registers=("a2", "a3", "a4", "a5"),
        word_size=8,
    ),
}

_FAMILIES = ("propagation", "memory", "isolation")

# Which of the program's outputs each family expects to come back tainted.
# Anything not named here must come back clean, so a backend that over-taints
# fails just as loudly as one that under-taints.
_EXPECTED_TAINT = {
    "propagation": {"out1", "out2", "slot0"},
    "memory": {"out4", "slot2"},
    "isolation": set(),
}

SCENARIO_PREFIXES = tuple(
    (f"taint.{family}", f"taint.{family}") for family in _FAMILIES
)

SCENARIO_INFOS = tuple(
    ScenarioInfo(
        prefix=f"taint.{family}",
        scenario=f"taint.{family}",
        tags=("scenario", "taint", "triton"),
        variants_source=from_arch_table(_SPECS),
        run_factory=just_run(),
        description=f"Triton taint tracking: {family}",
    )
    for family in _FAMILIES
)


def can_run(scenario: str, variant: str) -> bool:
    if not scenario.startswith("taint."):
        return False
    if scenario.split(".", 1)[1] not in _FAMILIES:
        return False
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def _apply_initial_taint(emulator, family: str, spec: TaintSpec, slot2: int) -> None:
    """Mark the inputs this family starts from, before the program runs."""
    tainted_input = spec.input_registers[0]
    if family == "propagation":
        emulator.taint_register(tainted_input)
    elif family == "memory":
        emulator.taint_memory(slot2, spec.word_size)
    elif family == "isolation":
        # Taint both sources and then take the taint straight back off; the
        # program must then produce a completely clean final state.
        emulator.taint_register(tainted_input)
        emulator.taint_memory(slot2, spec.word_size)
        emulator.untaint_register(tainted_input)
        emulator.untaint_memory(slot2, spec.word_size)
    else:
        raise ValueError(f"unknown taint family '{family}'")


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if args:
        raise SystemExit(f"{scenario} does not take extra arguments: {' '.join(args)}")

    import smallworld

    family = scenario.split(".", 1)[1]
    arch, engine = split_variant(variant)
    spec = _SPECS[arch]
    word = spec.word_size

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, "taint", arch)
    machine.add(code)
    set_register(cpu, spec.pc_register, code.address)

    set_register(cpu, spec.input_registers[0], TAINTED_INPUT)
    set_register(cpu, spec.input_registers[1], CLEAN_INPUT)

    scratch = smallworld.state.memory.Memory(SCRATCH_ADDRESS, SCRATCH_SIZE)
    scratch[0] = smallworld.state.BytesValue(b"\x00" * SCRATCH_SIZE, "taint scratch")
    machine.add(scratch)

    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(code.address + code.get_capacity())
    machine.apply(emulator)

    slots = [SCRATCH_ADDRESS + index * word for index in range(3)]
    # Every architecture Triton supports is little-endian, so the slot encoding
    # below does not need to consult the platform's byte order.
    # slot2 is the one the program only ever reads, so the harness supplies its
    # contents (and, for the `memory` family, its taint).
    emulator.write_memory_content(slots[2], SEEDED_SLOT.to_bytes(word, "little"))
    _apply_initial_taint(emulator, family, spec, slots[2])

    emulator.run()

    out1, out2, out3, out4 = spec.output_registers
    values = {
        "in0": (emulator.read_register(spec.input_registers[0]), 0),
        "in1": (emulator.read_register(spec.input_registers[1]), CLEAN_INPUT),
        "out1": (emulator.read_register(out1), TAINTED_INPUT + 1),
        "out2": (emulator.read_register(out2), TAINTED_INPUT + 1),
        "out3": (emulator.read_register(out3), CLEAN_INPUT),
        "out4": (emulator.read_register(out4), SEEDED_SLOT),
    }
    for index, slot in enumerate(slots):
        expected = (TAINTED_INPUT + 1, CLEAN_INPUT, SEEDED_SLOT)[index]
        actual = int.from_bytes(emulator.read_memory(slot, word), "little")
        values[f"slot{index}"] = (actual, expected)

    tainted = {
        name: (
            emulator.is_register_tainted(_register_for(spec, name))
            if name.startswith(("in", "out"))
            else emulator.is_memory_tainted(slots[int(name[-1])], word)
        )
        for name in values
    }

    expected_taint = _EXPECTED_TAINT[family]
    failures: list[str] = []
    for name in sorted(values):
        actual_value, expected_value = values[name]
        actual_taint = tainted[name]
        want_taint = name in expected_taint
        print(
            f"{scenario} {variant}: {name} = {actual_value:#x} tainted={actual_taint}"
        )
        if actual_value != expected_value:
            failures.append(
                f"{name} is {actual_value:#x}, expected {expected_value:#x}"
            )
        if actual_taint != want_taint:
            failures.append(f"{name} taint is {actual_taint}, expected {want_taint}")

    if failures:
        raise smallworld.exceptions.AnalysisError(
            f"{scenario} {variant}: " + "; ".join(failures)
        )
    return 0


def _register_for(spec: TaintSpec, name: str) -> str:
    if name == "in0":
        return spec.input_registers[0]
    if name == "in1":
        return spec.input_registers[1]
    return spec.output_registers[int(name[-1]) - 1]
