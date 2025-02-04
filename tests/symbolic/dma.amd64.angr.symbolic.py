import logging
import pathlib
import sys
import typing

import claripy

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=True, verbose=True)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
path = pathlib.Path(__file__)
basename = path.name.split(".")[0]
binfile = path.parent.parent / basename / (basename + ".amd64.bin")
code = smallworld.state.memory.code.Executable.from_filepath(
    binfile.as_posix(), address=0x1000
)
machine.add(code)

# Set the instruction pointer to the code entrypoint
cpu.rip.set(code.address)

# Initialize argument registers
numerator = int(sys.argv[1])
denominator = int(sys.argv[2])

cpu.rdi.set(numerator)
cpu.rdi.set_label("arg1")
cpu.rsi.set(denominator)
cpu.rsi.set_label("arg2")


class HDivModel(smallworld.state.models.mmio.SymbolicMemoryMappedModel):
    def __init__(self, address: int, nbytes: int):
        super().__init__(address, nbytes * 4)
        self.reg_size = nbytes
        self.num_addr = address
        self.den_addr = address + nbytes
        self.quo_addr = address + nbytes * 2
        self.rem_addr = address + nbytes * 3
        self.end_addr = address + nbytes * 4

        self.numerator = claripy.BVV(0, nbytes * 8)
        self.denominator = claripy.BVV(0, nbytes * 8)
        self.quotient = claripy.BVV(0, nbytes * 8)
        self.remainder = claripy.BVV(0, nbytes * 8)

    def on_read(
        self,
        emu: smallworld.emulators.Emulator,
        addr: int,
        size: int,
        content: claripy.ast.bv.BV,
    ) -> typing.Optional[claripy.ast.bv.BV]:
        if addr >= self.quo_addr and addr < self.rem_addr:
            self.numerator = claripy.BVV(0, self.reg_size * 8)
            self.denominator = claripy.BVV(0, self.reg_size * 8)
            start = (addr - self.quo_addr) * 8
            end = start + (size * 8) - 1

            return self.quotient[end:start]
        elif addr >= self.rem_addr and addr < self.end_addr:
            self.numerator = claripy.BVV(0, self.reg_size * 8)
            self.denominator = claripy.BVV(0, self.reg_size * 8)
            start = (addr - self.rem_addr) * 8
            end = start + (size * 8) - 1
            return self.remainder[end:start]
        else:
            raise smallworld.exceptions.AnalysisError(
                "Unexpected read from MMIO register {hex(addr)}"
            )

    def on_write(
        self,
        emu: smallworld.emulators.Emulator,
        addr: int,
        size: int,
        value: claripy.ast.bv.BV,
    ) -> None:
        if addr >= self.num_addr and addr < self.den_addr:
            start = (addr - self.num_addr) * 8
            end = start + (size * 8) - 1
            hi = (self.reg_size * 8) - 1
            lo = 0

            if hi > end:
                value = claripy.Concat(self.numerator[hi : end + 1], value)
            if start > lo:
                value = claripy.Concat(value, self.numerator[start - 1 : lo])
            self.numerator = value

        elif addr >= self.den_addr and addr < self.quo_addr:
            start = (addr - self.den_addr) * 8
            end = start + (size * 8) - 1
            hi = (self.reg_size * 8) - 1
            lo = 0

            if hi > end:
                value = claripy.Concat(self.denominator[hi : end + 1], value)
            if start > lo:
                value = claripy.Concat(value, self.denominator[start - 1 : lo])
            self.denominator = value

            self.quotient = self.numerator // self.denominator
            self.remainder = self.numerator % self.denominator
        else:
            raise smallworld.exceptions.AnalysisError(
                "Unexpected write to MMIO register {hex(addr)}"
            )


hdiv = HDivModel(0x50014000, 8)
machine.add(hdiv)

# Emulate
emulator = smallworld.emulators.AngrEmulator(platform)
emulator.enable_linear()
emulator.add_exit_point(cpu.rip.get() + code.get_capacity())
final_machine = machine.emulate(emulator)

# read out the final state
cpu = final_machine.get_cpu()
print(cpu.rax)
res = emulator.eval_atmost(cpu.rax.get(), 1)[0]
print(hex(res))
if res != (numerator // denominator):
    raise ValueError(f"Result {res} != {numerator} // {denominator}")
