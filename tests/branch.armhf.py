import logging
import sys

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a state object
state = smallworld.state.CPU.for_arch("arm", "v5t", "little")

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath(
    "branch.armel.bin", arch="arm", mode="v5t", base=0x1000, entry=0x1000
)
state.map(code)
state.pc.value = code.entry

# set input register
state.r0.value = int(sys.argv[1])

# now we can do a single micro-execution without error
emulator = smallworld.emulators.UnicornEmulator(
    arch=state.arch, mode=state.mode, endian=state.endian
)
final_state = emulator.emulate(state)

# read the result
print(final_state.r0)
