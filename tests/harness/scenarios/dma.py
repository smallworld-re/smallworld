from __future__ import annotations

import argparse
import dataclasses
import logging
from typing import Sequence

from .common import (
    PlatformSpec,
    load_raw_code,
    make_emulator,
    make_platform,
    maybe_enable_linear,
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


_SPECS = {
    "aarch64": DMASpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        pc_register="pc",
        result_register="w0",
        argument_registers=("x0", "x1"),
        mmio_address=0x50014000,
        mmio_width=8,
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "amd64": DMASpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pc_register="rip",
        result_register="eax",
        argument_registers=("rdi", "rsi"),
        mmio_address=0x50014000,
        mmio_width=8,
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "armel": DMASpec(
        platform=PlatformSpec("ARM_V5T", "LITTLE"),
        pc_register="pc",
        result_register="r0",
        argument_registers=("r0", "r1"),
        mmio_address=0x50004000,
        mmio_width=4,
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "armhf": DMASpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pc_register="pc",
        result_register="r0",
        argument_registers=("r0", "r1"),
        mmio_address=0x50014000,
        mmio_width=4,
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "i386": DMASpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        pc_register="eip",
        result_register="eax",
        argument_registers=("edi", "esi"),
        mmio_address=0x50014000,
        mmio_width=4,
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "la64": DMASpec(
        platform=PlatformSpec("LOONGARCH64", "LITTLE"),
        pc_register="pc",
        result_register="a0",
        argument_registers=("a0", "a1"),
        mmio_address=0x50014000,
        mmio_width=8,
        engines=("angr", "pcode"),
    ),
    "m68k": DMASpec(
        platform=PlatformSpec("M68K", "BIG"),
        pc_register="pc",
        result_register="d0",
        argument_registers=("d0", "d1"),
        mmio_address=0x50014000,
        mmio_width=4,
        engines=("unicorn", "pcode"),
    ),
    "mips": DMASpec(
        platform=PlatformSpec("MIPS32", "BIG"),
        pc_register="pc",
        result_register="v0",
        argument_registers=("a0", "a1"),
        mmio_address=0x50014000,
        mmio_width=4,
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "mipsel": DMASpec(
        platform=PlatformSpec("MIPS32", "LITTLE"),
        pc_register="pc",
        result_register="v0",
        argument_registers=("a0", "a1"),
        mmio_address=0x50014000,
        mmio_width=4,
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "mips64": DMASpec(
        platform=PlatformSpec("MIPS64", "BIG"),
        pc_register="pc",
        result_register="v0",
        argument_registers=("a0", "a1"),
        mmio_address=0x50014000,
        mmio_width=8,
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "mips64el": DMASpec(
        platform=PlatformSpec("MIPS64", "LITTLE"),
        pc_register="pc",
        result_register="v0",
        argument_registers=("a0", "a1"),
        mmio_address=0x50014000,
        mmio_width=8,
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "msp430": DMASpec(
        platform=PlatformSpec("MSP430", "LITTLE"),
        pc_register="pc",
        result_register="r15",
        argument_registers=("r15", "r14"),
        mmio_address=0x5000,
        mmio_width=2,
        engines=("pcode",),
    ),
    "msp430x": DMASpec(
        platform=PlatformSpec("MSP430X", "LITTLE"),
        pc_register="pc",
        result_register="r15",
        argument_registers=("r15", "r14"),
        mmio_address=0x5000,
        mmio_width=2,
        engines=("angr", "pcode"),
    ),
    "ppc": DMASpec(
        platform=PlatformSpec("POWERPC32", "BIG"),
        pc_register="pc",
        result_register="r3",
        argument_registers=("r3", "r4"),
        mmio_address=0x50014000,
        mmio_width=4,
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "ppc64": DMASpec(
        platform=PlatformSpec("POWERPC64", "BIG"),
        pc_register="pc",
        result_register="r3",
        argument_registers=("r3", "r4"),
        mmio_address=0x50014000,
        mmio_width=8,
        engines=("unicorn", "angr", "pcode"),
    ),
    "riscv64": DMASpec(
        platform=PlatformSpec("RISCV64", "LITTLE"),
        pc_register="pc",
        result_register="a0",
        argument_registers=("a0", "a1"),
        mmio_address=0x50014000,
        mmio_width=8,
        engines=("unicorn", "angr", "pcode"),
    ),
    "xtensa": DMASpec(
        platform=PlatformSpec("XTENSA", "LITTLE"),
        pc_register="pc",
        result_register="a2",
        argument_registers=("a2", "a3"),
        mmio_address=0x50014000,
        mmio_width=4,
        engines=("angr", "pcode"),
        pc_offset=4,
        exit_offset=0xC,
    ),
}


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
    maybe_enable_linear(smallworld, emulator, engine)
    if spec.exit_offset is not None:
        emulator.add_exit_point(code.address + spec.exit_offset)
    else:
        emulator.add_exit_point(code.address + code.get_capacity())

    final_machine = machine.emulate(emulator)
    value = _read_register_value(getattr(final_machine.get_cpu(), spec.result_register))
    print(hex(value))
    return 0
