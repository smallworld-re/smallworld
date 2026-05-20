from __future__ import annotations

import argparse
import dataclasses
import logging
from typing import Any, Sequence

from .spec import ScenarioInfo, assert_contains, from_arch_table
from .common import (
    PlatformSpec,
    build_specs,
    load_raw_code,
    make_emulator,
    make_platform,
    set_register,
    split_variant,
)


@dataclasses.dataclass(frozen=True)
class DMASpec:
    platform: PlatformSpec
    pc_register: str
    result_register: str
    argument_registers: tuple[str, str]
    mmio_address: int
    mmio_width: int
    engines: tuple[str, ...]
    pc_offset: int = 0
    exit_offset: int | None = None


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
    "msp430",
    "msp430x",
    "ppc",
    "ppc64",
    "riscv64",
    "tricore",
    "xtensa",
)

_PER_ARCH: dict[str, dict[str, Any]] = {
    "aarch64": {"result_register": "w0", "argument_registers": ("x0", "x1")},
    "amd64": {"argument_registers": ("rdi", "rsi")},
    "armel": {"argument_registers": ("r0", "r1"), "mmio_address": 0x50004000},
    "armhf": {"argument_registers": ("r0", "r1")},
    "i386": {"argument_registers": ("edi", "esi")},
    "la64": {"argument_registers": ("a0", "a1")},
    "m68k": {"argument_registers": ("d0", "d1")},
    "mips": {"argument_registers": ("a0", "a1")},
    "mipsel": {"argument_registers": ("a0", "a1")},
    "mips64": {"argument_registers": ("a0", "a1")},
    "mips64el": {"argument_registers": ("a0", "a1")},
    "msp430": {
        "result_register": "r15",
        "argument_registers": ("r15", "r14"),
        "mmio_address": 0x5000,
    },
    "msp430x": {
        "result_register": "r15",
        "argument_registers": ("r15", "r14"),
        "mmio_address": 0x5000,
    },
    "ppc": {"argument_registers": ("r3", "r4")},
    "ppc64": {"argument_registers": ("r3", "r4")},
    "riscv64": {"argument_registers": ("a0", "a1")},
    "tricore": {"argument_registers": ("d4", "d5")},
    "xtensa": {
        "argument_registers": ("a2", "a3"),
        "pc_offset": 4,
        "exit_offset": 0x10,
    },
}

_SPECS = build_specs(
    DMASpec,
    _ARCHS,
    # The MMIO register width always matches the pointer width for this scenario.
    field_aliases={"mmio_width": "pointer_size"},
    common={"mmio_address": 0x50014000},
    per_arch=_PER_ARCH,
)

SCENARIO_PREFIXES = (("dma", "dma"),)

NATIVE_PARITY = True

SCENARIO_INFO = ScenarioInfo(
    prefix="dma",
    scenario="dma",
    tags=("scenario", "dma"),
    variants_source=from_arch_table(
        _SPECS,
        skip_reasons={
            "armel.panda": "Waiting for panda-ng fix",
            "ppc64": "Unicorn ppc64 support buggy",
        },
    ),
    run_factory=assert_contains("0x5", args=("10", "2")),
)


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "dma":
        return False
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def _read_register_value(register) -> int:
    if hasattr(register, "get_content"):
        return register.get_content()
    return register.get()


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog=f"run_case.py {scenario} {variant}")
    parser.add_argument("numerator", type=lambda text: int(text, 0), help="dividend")
    parser.add_argument("denominator", type=lambda text: int(text, 0), help="divisor")
    ns = parser.parse_args(list(args))

    import smallworld

    arch, engine = split_variant(variant)
    spec = _SPECS[arch]

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, "dma", arch)
    machine.add(code)
    set_register(cpu, spec.pc_register, code.address + spec.pc_offset)
    set_register(cpu, spec.argument_registers[0], ns.numerator)
    set_register(cpu, spec.argument_registers[1], ns.denominator)

    endianness = "little" if spec.platform.byteorder == "LITTLE" else "big"

    class HDivModel(smallworld.state.models.mmio.MemoryMappedModel):
        def __init__(self, address: int, nbytes: int):
            super().__init__(address, nbytes * 4)
            self.reg_size = nbytes
            self.num_addr = address
            self.den_addr = address + nbytes
            self.quo_addr = address + nbytes * 2
            self.rem_addr = address + nbytes * 3
            self.end_addr = address + nbytes * 4

            self.numerator = 0
            self.denominator = 0
            self.quotient = 0
            self.remainder = 0

        def on_read(self, emu, addr: int, size: int, content: bytes) -> bytes:
            if self.quo_addr <= addr < self.rem_addr:
                self.numerator = 0
                self.denominator = 0
                start = addr - self.quo_addr
                end = start + size
                return self.quotient.to_bytes(self.reg_size, endianness)[start:end]
            if self.rem_addr <= addr < self.end_addr:
                self.numerator = 0
                self.denominator = 0
                start = addr - self.rem_addr
                end = start + size
                return self.remainder.to_bytes(self.reg_size, endianness)[start:end]
            raise smallworld.exceptions.AnalysisError(
                f"Unexpected read from MMIO register {hex(addr)}"
            )

        def on_write(self, emu, addr: int, size: int, value: bytes) -> None:
            if self.num_addr <= addr < self.den_addr:
                start = addr - self.num_addr
                end = start + size
                num_bytes = bytearray(
                    self.numerator.to_bytes(self.reg_size, endianness)
                )
                num_bytes[start:end] = value
                self.numerator = int.from_bytes(num_bytes, endianness)
                return
            if self.den_addr <= addr < self.quo_addr:
                start = addr - self.den_addr
                end = start + size
                den_bytes = bytearray(
                    self.denominator.to_bytes(self.reg_size, endianness)
                )
                den_bytes[start:end] = value
                self.denominator = int.from_bytes(den_bytes, endianness)
                if self.denominator != 0:
                    self.quotient = self.numerator // self.denominator
                    self.remainder = self.numerator % self.denominator
                return
            raise smallworld.exceptions.AnalysisError(
                f"Unexpected write to MMIO register {hex(addr)}"
            )

    machine.add(HDivModel(spec.mmio_address, spec.mmio_width))

    emulator = make_emulator(smallworld, platform, engine)
    if spec.exit_offset is not None:
        emulator.add_exit_point(code.address + spec.exit_offset)
    elif arch == "amd64" and engine in {"panda", "pcode"}:
        # The amd64 DMA case ends with `hlt`. PANDA wedges on that instruction
        # and Ghidra tears down the JVM, leaving the process wedged. Stop at
        # the final instruction boundary instead of one-past-the-end.
        emulator.add_exit_point(code.address + code.get_capacity() - 1)
    else:
        emulator.add_exit_point(code.address + code.get_capacity())

    final_machine = machine.emulate(emulator)
    value = _read_register_value(getattr(final_machine.get_cpu(), spec.result_register))
    print(hex(value))
    return 0
