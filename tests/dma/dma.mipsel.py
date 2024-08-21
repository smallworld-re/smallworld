import logging
import sys

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

logger = logging.getLogger("test")

# create a state object
state = smallworld.state.CPU.for_arch("mips", "mips32", "little")

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath(
    "dma.mipsel.bin",
    base=0x1000,
    entry=0x1000,
    arch="mips",
    mode="mips32",
    format="blob",
)
state.map(code)
state.pc.value = 0x1000

# set input register
state.a0.value = int(sys.argv[1])
state.a1.value = int(sys.argv[2])
print(state.a0.value)
print(state.a1.value)


class HDivModel(smallworld.state.mmio.MMIOModel):
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
        self, emu: smallworld.emulators.Emulator, addr: int, size: int
    ) -> bytes:
        if addr >= self.quo_addr and addr < self.rem_addr:
            self.numerator = 0
            self.denominator = 0
            start = addr - self.quo_addr
            end = start + size
            return self.quotient.to_bytes(self.reg_size, "little")[start:end]
        elif addr >= self.rem_addr and addr < self.end_addr:
            self.numerator = 0
            self.denominator = 0
            start = addr - self.rem_addr
            end = start + size
            return self.remainder.to_bytes(self.reg_size, "little")[start:end]
        else:
            raise smallworld.exceptions.AnalysisError(
                f"Unexpected read from MMIO register {hex(addr)}"
            )

    def on_write(
        self, emu: smallworld.emulators.Emulator, addr: int, size: int, value: bytes
    ) -> None:
        if addr >= self.num_addr and addr < self.den_addr:
            start = addr - self.num_addr
            end = start + size
            num_bytes = bytearray(self.numerator.to_bytes(self.reg_size, "little"))
            num_bytes[start:end] = value
            self.numerator = int.from_bytes(num_bytes, "little")
        elif addr >= self.den_addr and addr < self.quo_addr:
            start = addr - self.den_addr
            end = start + size
            den_bytes = bytearray(self.denominator.to_bytes(self.reg_size, "little"))
            den_bytes[start:end] = value
            self.denominator = int.from_bytes(den_bytes, "little")

            if self.denominator != 0:
                # TODO: I have no idea how the real thing handles DIV0
                self.quotient = self.numerator // self.denominator
                self.remainder = self.numerator % self.denominator
        else:
            raise smallworld.exceptions.AnalysisError(
                f"Unexpected write to MMIO register {hex(addr)}"
            )


hdiv = HDivModel(0x50014000, 4)
state.map(hdiv)

# now we can do a single micro-execution without error
emulator = smallworld.emulators.UnicornEmulator(
    arch=state.arch, mode=state.mode, byteorder=state.byteorder
)

final_state = emulator.emulate(state)

# read the result
print(final_state.v0)
