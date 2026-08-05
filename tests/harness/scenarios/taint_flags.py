"""Flag-mediated data flow (amd64).

A value produced from tainted inputs *through the condition flags* is still
tracked: propagation uses capstone's register-access information, which reports
the implicit flags-register accesses of ``cmp``/``setcc``. This is intentionally
conservative -- the whole flags register is one taint unit, so taint can
over-approximate across independent condition codes -- but the flow is captured
on both the concrete and symbolic backends.
"""

from __future__ import annotations

import logging
from typing import Sequence

from .common import PlatformSpec, load_raw_code, make_platform, split_variant
from .spec import ScenarioInfo, just_run
from .taint_common import Checker, make_taint_emulator

_PLATFORM = PlatformSpec("X86_64", "LITTLE")
_ENGINES = ("unicorn", "panda", "angr")

SCENARIO_PREFIXES = (("taint_flags", "taint_flags"),)
NATIVE_PARITY = False


def _variants():
    return [("amd64" if e == "unicorn" else f"amd64.{e}", None, {}) for e in _ENGINES]


SCENARIO_INFO = ScenarioInfo(
    prefix="taint_flags",
    scenario="taint_flags",
    tags=("scenario", "taint"),
    variants_source=_variants,
    run_factory=just_run(),
)


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "taint_flags":
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
    code = load_raw_code(smallworld, "taint_flags", arch)
    machine.add(code)
    cpu.rip.set(code.address)
    machine.add_exit_point(code.address + code.get_capacity())

    cpu.rdi.set(0x11)
    cpu.rdi.set_label("a")
    cpu.rsi.set(0x22)
    cpu.rsi.set_label("b")
    cpu.rax.set(0x0)  # sete writes al; the rest of rax stays 0/untainted

    emu = make_taint_emulator(smallworld, engine, platform)
    ocpu = machine.emulate(emu).get_cpu()

    c = Checker()
    # `cmp a, b` sets the flags from the tainted inputs; `sete al` reads them.
    # al therefore carries the taint that flowed through the flags register.
    c.check("flag-mediated flow tracked (al)", ocpu.rax.get_taint(), {"a", "b"})
    return c.result()
