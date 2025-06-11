import logging
import sys

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=True, verbose=True)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.POWERPC32, smallworld.platforms.Byteorder.BIG
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
code = smallworld.state.memory.code.Executable.from_filepath(
    __file__.replace(".py", ".bin").replace(".angr", "").replace(".panda", ""),
    address=0x1000,
)
machine.add(code)

# Set the instruction pointer to the code entrypoint
cpu.pc.set(code.address)

# Initialize argument registers
cpu.r3.set(int(sys.argv[1]))
cpu.r4.set(int(sys.argv[2]))


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

    def on_read(
        self, emu: smallworld.emulators.Emulator, addr: int, size: int, content: bytes
    ) -> bytes:
        if addr >= self.quo_addr and addr < self.rem_addr:
            self.numerator = 0
            self.denominator = 0
            start = addr - self.quo_addr
            end = start + size
            return self.quotient.to_bytes(self.reg_size, "big")[start:end]
        elif addr >= self.rem_addr and addr < self.end_addr:
            self.numerator = 0
            self.denominator = 0
            start = addr - self.rem_addr
            end = start + size
            return self.remainder.to_bytes(self.reg_size, "big")[start:end]
        else:
            raise smallworld.exceptions.AnalysisError(
                "Unexpected read from MMIO register {hex(addr)}"
            )

    def on_write(
        self, emu: smallworld.emulators.Emulator, addr: int, size: int, value: bytes
    ) -> None:
        if addr >= self.num_addr and addr < self.den_addr:
            start = addr - self.num_addr
            end = start + size
            num_bytes = bytearray(self.numerator.to_bytes(self.reg_size, "big"))
            num_bytes[start:end] = value
            self.numerator = int.from_bytes(num_bytes, "big")
        elif addr >= self.den_addr and addr < self.quo_addr:
            start = addr - self.den_addr
            end = start + size
            den_bytes = bytearray(self.denominator.to_bytes(self.reg_size, "big"))
            den_bytes[start:end] = value
            self.denominator = int.from_bytes(den_bytes, "big")

            if self.denominator != 0:
                # TODO: I have no idea how the real thing handles DIV0
                self.quotient = self.numerator // self.denominator
                self.remainder = self.numerator % self.denominator
        else:
            raise smallworld.exceptions.AnalysisError(
                "Unexpected write to MMIO register {hex(addr)}"
            )


hdiv = HDivModel(0x50014000, 4)
machine.add(hdiv)

# Emulate
emulator = smallworld.emulators.AngrEmulator(platform)
emulator.enable_linear()
emulator.add_exit_point(cpu.pc.get() + code.get_capacity())
final_machine = machine.emulate(emulator)

# read out the final state
cpu = final_machine.get_cpu()
print(hex(cpu.r3.get_content()))
