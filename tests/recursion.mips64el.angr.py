import logging
import sys

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a state object
state = smallworld.state.CPU.for_arch("mips", "mips64", "little")

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath(
    "recursion.mips64el.bin",
    arch="mips",
    mode="mips64",
    format="blob",
    base=0x1000,
    entry=0x1000,
)
state.map(code)
state.pc.value = 0x1000

# set input register
state.a0.value = int(sys.argv[-1])
print(state.a0.value)

# Set up stack
stack = smallworld.state.Stack(address=0x2000, size=0x8000)
sp = stack.push(value=0xFFFFFFFF, size=8, type=int, label="fake return address")
state.map(stack)
state.sp.value = sp

# now we can do a single micro-execution without error
emulator = smallworld.emulators.AngrEmulator(
    arch=state.arch, mode=state.mode, byteorder=state.byteorder
)
emulator.enable_linear()
final_state = emulator.emulate(state)

# read the result
print(final_state.v0)
