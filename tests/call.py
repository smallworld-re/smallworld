import logging
import sys

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a state object
state = smallworld.state.CPU.for_arch("x86", "64", "little")

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath(
    "call.bin", arch="x86", mode="64", format="blob", base=0x1000, entry=0x1000
)
state.map(code)
state.rip.value = code.entry

# set input register
state.rdi.value = int(sys.argv[1])

# Set up stack
stack = smallworld.state.Stack(address=0x2000, size=0x8000)
rsp = stack.push(value=0xFFFFFFFF, size=8, type=int, label="fake return address")
state.map(stack)
state.rsp.value = rsp

# now we can do a single micro-execution without error
emulator = smallworld.emulators.UnicornEmulator(
    arch=state.arch, mode=state.mode, byteorder=state.byteorder
)
final_state = emulator.emulate(state)

# read the result
print(final_state.eax)
