import logging
import sys

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a state object
state = smallworld.state.CPU.for_arch("aarch64", "v8a", "little")

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath(
    "square.aarch64.bin",
    base=0x1000,
    entry=0x1000,
    arch="aarch64",
    mode="v8a",
    format="blob",
)
state.map(code)
state.pc.value = 0x1000

# set input register
state.x0.value = int(sys.argv[-1])
print(state.x0.value)

# now we can do a single micro-execution without error
emulator = smallworld.emulators.AngrEmulator(
    arch=state.arch, mode=state.mode, byteorder=state.byteorder
)
emulator.enable_linear()
final_state = emulator.emulate(state)

# read the result
print(final_state.x0)
