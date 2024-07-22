import logging
import sys

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

log = logging.getLogger("__main__")

# create a state object
state = smallworld.state.CPU.for_arch("powerpc", "ppc64", "big")

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath(
    "strlen.ppc64.bin",
    arch="powerpc",
    mode="ppc64",
    format="blob",
    base=0x1000,
    entry=0x1000,
)
state.map(code)
state.pc.value = code.entry

string = sys.argv[1].encode("utf-8")

# Set up stack
stack = smallworld.state.Stack(address=0x2000, size=0x8000, byteorder="big")
arg1 = stack.push(value=string, size=len(string))
sp = stack.push(value=0xFFFFFFFF, size=8, type=int, label="fake return address")
state.map(stack)
state.sp.value = sp

# Set input regsiter
state.r3.value = arg1

# now we can do a single micro-execution without error
emulator = smallworld.emulators.AngrEmulator(
    arch=state.arch, mode=state.mode, byteorder=state.byteorder
)
emulator.enable_linear()
final_state = emulator.emulate(state, single_step=True)
# read the result
print(final_state.r3)
