"""Address-taint behavior and its limitations (amd64).

Loads through a tainted base pointer and a tainted index register, where the
loaded memory is itself untainted. By default (data-flow only) the address
taint stays out of the loaded value; with ``taint_addresses=True`` it flows in.
The symbolic backend (angr) does not propagate address taint -- a documented
best-effort limitation -- which this scenario demonstrates.
"""

from __future__ import annotations

import logging
from typing import Sequence

from .common import PlatformSpec, load_raw_code, make_platform, split_variant
from .spec import ScenarioInfo, just_run
from .taint_common import Checker, make_taint_emulator

_PLATFORM = PlatformSpec("X86_64", "LITTLE")
_ENGINES = ("unicorn", "panda", "angr")
_BUFFER = 0x6000

SCENARIO_PREFIXES = (("taint_addr", "taint_addr"),)
NATIVE_PARITY = False


def _variants():
    return [("amd64" if e == "unicorn" else f"amd64.{e}", None, {}) for e in _ENGINES]


SCENARIO_INFO = ScenarioInfo(
    prefix="taint_addr",
    scenario="taint_addr",
    tags=("scenario", "taint"),
    variants_source=_variants,
    run_factory=just_run(),
)


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "taint_addr":
        return False
    arch, engine = split_variant(variant)
    return arch == "amd64" and engine in _ENGINES


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    import smallworld

    arch, engine = split_variant(variant)
    smallworld.logging.setup_logging(level=logging.INFO)
    platform = make_platform(smallworld, _PLATFORM)

    def emulate(taint_addresses: bool):
        machine = smallworld.state.Machine()
        cpu = smallworld.state.cpus.CPU.for_platform(platform)
        machine.add(cpu)
        code = load_raw_code(smallworld, "taint_addr", arch)
        machine.add(code)
        cpu.rip.set(code.address)
        machine.add_exit_point(code.address + code.get_capacity())

        cpu.rdi.set(_BUFFER)  # base pointer
        cpu.rdi.set_label("ptr")
        cpu.rbx.set(_BUFFER)  # base pointer, unlabeled
        cpu.rcx.set(0x8)  # index
        cpu.rcx.set_label("idx")

        # The loaded bytes are unlabeled, so any taint on the destinations comes
        # only from the address registers.
        data = smallworld.state.memory.Memory(_BUFFER, 0x1000)
        data[0] = smallworld.state.IntegerValue(0, 8, None, platform.byteorder)
        data[8] = smallworld.state.IntegerValue(0, 8, None, platform.byteorder)
        machine.add(data)

        emu = make_taint_emulator(
            smallworld, engine, platform, taint_addresses=taint_addresses
        )
        return machine.emulate(emu).get_cpu()

    c = Checker()
    if engine == "unicorn":
        ocpu = emulate(taint_addresses=False)
        c.check("data-flow: base ptr excluded (rax)", ocpu.rax.get_taint(), set())
        c.check("data-flow: index excluded (rdx)", ocpu.rdx.get_taint(), set())
        ocpu = emulate(taint_addresses=True)
        c.check("addr-taint: base ptr flows (rax)", ocpu.rax.get_taint(), {"ptr"})
        c.check("addr-taint: index flows (rdx)", ocpu.rdx.get_taint(), {"idx"})
    elif engine == "panda":
        ocpu = emulate(taint_addresses=True)
        c.check("addr-taint: base ptr flows (rax)", ocpu.rax.get_taint(), {"ptr"})
        c.check("addr-taint: index flows (rdx)", ocpu.rdx.get_taint(), {"idx"})
    else:  # symbolic backends do not propagate address taint (limitation)
        ocpu = emulate(taint_addresses=True)
        c.check_true(
            "limitation: symbolic base-ptr taint not propagated",
            "ptr" not in ocpu.rax.get_taint(),
            f"rax taint={ocpu.rax.get_taint()!r}",
        )
        c.check_true(
            "limitation: symbolic index taint not propagated",
            "idx" not in ocpu.rdx.get_taint(),
            f"rdx taint={ocpu.rdx.get_taint()!r}",
        )
    return c.result()
