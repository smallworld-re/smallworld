from __future__ import annotations

import dataclasses
import logging
from typing import Sequence, Tuple

from .common import PlatformSpec, load_raw_code, make_platform, split_variant
from .spec import ScenarioInfo, from_arch_table, just_run
from .taint_common import SYMBOLIC_ENGINES, make_taint_emulator


@dataclasses.dataclass(frozen=True)
class TaintSpec:
    platform: PlatformSpec
    pc: str  # program counter register
    a: str  # taint source "a"
    b: str  # taint source "b"
    ptr: str  # pointer to the scratch buffer
    dst_add: str  # register that receives a + b
    dst_load: str  # register that receives the value loaded from the buffer
    clear: str  # register cleared by the taint-clearing idiom
    engines: Tuple[str, ...]


# Which taint engines apply to each architecture. Concrete propagation: Unicorn
# and PANDA. Symbolic propagation: angr. (Styx is ARM-only and does not yet
# support taint; ARM coverage comes from Unicorn and PANDA.)
_UNICORN = ("unicorn",)
_UNICORN_PANDA = ("unicorn", "panda")
_UNICORN_PANDA_ANGR = ("unicorn", "panda", "angr")
_UNICORN_PANDA_SYMBOLIC = ("unicorn", "panda", "angr", "pcode_symbolic")

_SPECS = {
    "amd64": TaintSpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pc="rip",
        a="rdi",
        b="rsi",
        ptr="rdx",
        dst_add="rax",
        dst_load="rcx",
        clear="r8",
        engines=_UNICORN_PANDA_SYMBOLIC,
    ),
    "i386": TaintSpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        pc="eip",
        a="edi",
        b="esi",
        ptr="ebx",
        dst_add="eax",
        dst_load="ecx",
        clear="edx",
        engines=_UNICORN_PANDA_ANGR,
    ),
    "aarch64": TaintSpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        pc="pc",
        a="x0",
        b="x1",
        ptr="x2",
        dst_add="x3",
        dst_load="x4",
        clear="x5",
        engines=_UNICORN_PANDA_ANGR,
    ),
    "armel": TaintSpec(
        platform=PlatformSpec("ARM_V5T", "LITTLE"),
        pc="pc",
        a="r0",
        b="r1",
        ptr="r2",
        dst_add="r3",
        dst_load="r4",
        clear="r5",
        engines=_UNICORN_PANDA,
    ),
    "armhf": TaintSpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pc="pc",
        a="r0",
        b="r1",
        ptr="r2",
        dst_add="r3",
        dst_load="r4",
        clear="r5",
        engines=_UNICORN_PANDA,
    ),
    "mips": TaintSpec(
        platform=PlatformSpec("MIPS32", "BIG"),
        pc="pc",
        a="a0",
        b="a1",
        ptr="a3",
        dst_add="a2",
        dst_load="t0",
        clear="t1",
        engines=_UNICORN_PANDA,
    ),
    "mipsel": TaintSpec(
        platform=PlatformSpec("MIPS32", "LITTLE"),
        pc="pc",
        a="a0",
        b="a1",
        ptr="a3",
        dst_add="a2",
        dst_load="t0",
        clear="t1",
        engines=_UNICORN,
    ),
}


SCENARIO_PREFIXES = (("taint", "taint"),)

NATIVE_PARITY = False

SCENARIO_INFO = ScenarioInfo(
    prefix="taint",
    scenario="taint",
    tags=("scenario", "taint"),
    variants_source=from_arch_table(_SPECS),
    run_factory=just_run(),
)

_BUFFER = 0x6000

# Engines that can be instantiated multiple times within one process. PANDA (and
# Styx) run a full emulator instance backed by global QEMU/native state that
# cannot be re-created per test, so they run only the single-emulation core
# checks below. (Symbolic backends leave the pointer unlabeled -- see below --
# and so also run only the core checks here.)
_MULTI_INSTANCE_ENGINES = {"unicorn"}


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "taint":
        return False
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    import smallworld

    arch, engine = split_variant(variant)
    spec = _SPECS[arch]

    smallworld.logging.setup_logging(level=logging.INFO)
    platform = make_platform(smallworld, spec.platform)

    failures: list = []

    def emulate(taint: bool, taint_addresses: bool, label_ptr: bool):
        machine = smallworld.state.Machine()
        cpu = smallworld.state.cpus.CPU.for_platform(platform)
        machine.add(cpu)

        code = load_raw_code(smallworld, "taint", arch)
        machine.add(code)
        getattr(cpu, spec.pc).set(code.address)
        machine.add_exit_point(code.address + code.get_capacity())

        getattr(cpu, spec.a).set(0x11)
        getattr(cpu, spec.a).set_label("a")
        getattr(cpu, spec.b).set(0x22)
        getattr(cpu, spec.b).set_label("b")
        getattr(cpu, spec.clear).set(0x99)
        getattr(cpu, spec.clear).set_label("clearme")
        getattr(cpu, spec.ptr).set(_BUFFER)
        if label_ptr:
            getattr(cpu, spec.ptr).set_label("ptr")

        data = smallworld.state.memory.Memory(_BUFFER, 0x1000)
        data[0] = smallworld.state.IntegerValue(0, 8, None, platform.byteorder)
        machine.add(data)

        emu = make_taint_emulator(
            smallworld, engine, platform, taint=taint, taint_addresses=taint_addresses
        )
        out = machine.emulate(emu)
        ocpu = out.get_cpu()

        mem_taint = set()
        for m in out.members(smallworld.state.memory.Memory):
            if m.address == _BUFFER:
                mem_taint = m[0].get_taint()
        return ocpu, mem_taint

    def check(name: str, got, want) -> None:
        ok = got == want
        print(
            f"{'EXPECTED' if ok else 'UNEXPECTED'}  {name}: got={got!r} want={want!r}"
        )
        if not ok:
            failures.append(name)

    # Core behaviors, verifiable in a single emulation: source labels propagate
    # through registers and memory, arithmetic unions taint, and xor clears it.
    # For concrete engines the pointer is also labeled so the same run exercises
    # the default address-taint-off policy (the tainted pointer stays out of the
    # loaded value).
    concrete = engine not in SYMBOLIC_ENGINES
    ocpu, mem_taint = emulate(taint=True, taint_addresses=False, label_ptr=concrete)
    check("reg->reg->add union", getattr(ocpu, spec.dst_add).get_taint(), {"a", "b"})
    check("reg->mem store", mem_taint, {"a", "b"})
    check("mem->reg load", getattr(ocpu, spec.dst_load).get_taint(), {"a", "b"})
    check("xor clears taint", getattr(ocpu, spec.clear).get_taint(), set())
    check("source preserved", getattr(ocpu, spec.a).get_taint(), {"a"})
    if concrete:
        check(
            "addr-taint off: pointer excluded",
            getattr(ocpu, spec.dst_load).get_taint(),
            {"a", "b"},
        )

    # The remaining checks each need an additional emulation instance.
    if engine in _MULTI_INSTANCE_ENGINES:
        # Off by default: without the flag, taint is not tracked (content is
        # still correct).
        ocpu, _ = emulate(taint=False, taint_addresses=False, label_ptr=False)
        check(
            "off-by-default: no taint", getattr(ocpu, spec.dst_add).get_taint(), set()
        )
        check(
            "off-by-default: content correct",
            getattr(ocpu, spec.dst_add).get(),
            0x11 + 0x22,
        )

        # Address taint ON: the pointer label flows into the loaded value.
        ocpu, _ = emulate(taint=True, taint_addresses=True, label_ptr=True)
        check(
            "addr-taint on: pointer included",
            getattr(ocpu, spec.dst_load).get_taint(),
            {"a", "b", "ptr"},
        )

    if failures:
        print(f"UNEXPECTED  {len(failures)} failed: {failures}")
        return 1
    print("EXPECTED  No unexpected results")
    return 0
