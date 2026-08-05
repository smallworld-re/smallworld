"""Comprehensive taint-propagation semantics (amd64).

One straight-line program, one emulation, many assertions -- so it runs on
every engine including the single-instance backends (PANDA). The propagation
engine is architecture-generic, so amd64 exercises all the relevant code paths;
cross-architecture breadth lives in the ``taint`` scenario.
"""

from __future__ import annotations

import logging
from typing import Sequence

from .common import PlatformSpec, load_raw_code, make_platform, split_variant
from .spec import ScenarioInfo, just_run
from .taint_common import Checker, make_taint_emulator

_PLATFORM = PlatformSpec("X86_64", "LITTLE")
_ENGINES = ("unicorn", "panda", "angr", "pcode_symbolic")
_BUFFER = 0x6000

SCENARIO_PREFIXES = (("taint_ops", "taint_ops"),)
NATIVE_PARITY = False


def _variants():
    return [("amd64" if e == "unicorn" else f"amd64.{e}", None, {}) for e in _ENGINES]


SCENARIO_INFO = ScenarioInfo(
    prefix="taint_ops",
    scenario="taint_ops",
    tags=("scenario", "taint"),
    variants_source=_variants,
    run_factory=just_run(),
)


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "taint_ops":
        return False
    arch, engine = split_variant(variant)
    return arch == "amd64" and engine in _ENGINES


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    import smallworld

    arch, engine = split_variant(variant)
    smallworld.logging.setup_logging(level=logging.INFO)
    platform = make_platform(smallworld, _PLATFORM)

    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, "taint_ops", arch)
    machine.add(code)
    cpu.rip.set(code.address)
    machine.add_exit_point(code.address + code.get_capacity())

    for reg, value, label in (
        ("rdi", 0x11, "a"),
        ("rsi", 0x22, "b"),
        ("rdx", 0x33, "c"),
        ("r10", 0x44, "d"),
        ("r9", 0x55, "e"),
        ("r12", 0x66, "f"),
        ("r14", 0x77, "g"),
    ):
        getattr(cpu, reg).set(value)
        getattr(cpu, reg).set_label(label)
    cpu.rbx.set(_BUFFER)  # pointer to the scratch buffer, unlabeled
    cpu.r13.set(0x0)  # untainted value, unlabeled

    data = smallworld.state.memory.Memory(_BUFFER, 0x1000)
    data[0] = smallworld.state.IntegerValue(0, 8, None, platform.byteorder)
    machine.add(data)

    emu = make_taint_emulator(smallworld, engine, platform)
    out = machine.emulate(emu)
    ocpu = out.get_cpu()

    mem_taint = set()
    for m in out.members(smallworld.state.memory.Memory):
        if m.address == _BUFFER:
            mem_taint = m[0].get_taint()

    c = Checker()
    c.check("register copy + arithmetic union (rax)", ocpu.rax.get_taint(), {"a", "b"})
    c.check("register -> memory store", mem_taint, {"a", "b"})
    c.check("memory -> register load (rcx)", ocpu.rcx.get_taint(), {"a", "b"})
    c.check("xor r,r clears taint (rdx)", ocpu.rdx.get_taint(), set())
    c.check("sub r,r clears taint (r8)", ocpu.r8.get_taint(), set())
    c.check("overwrite from untainted clears (r9)", ocpu.r9.get_taint(), set())
    c.check("three-source union (r15)", ocpu.r15.get_taint(), {"a", "b", "f"})
    c.check("byte-granular propagation (r14)", ocpu.r14.get_taint(), {"b", "g"})
    c.check("no spurious taint (r13)", ocpu.r13.get_taint(), set())
    c.check("source register preserved (rdi)", ocpu.rdi.get_taint(), {"a"})
    return c.result()
