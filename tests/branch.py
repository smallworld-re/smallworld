import logging
import sys

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a state object
state = smallworld.cpus.AMD64CPUState()

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath("branch.bin", base=0x1000, entry=0x1000)
state.map(code)
state.rip.value = code.entry

# set input register
state.rdi.value = int(sys.argv[1])

# now we can do a single micro-execution without error
final_state = smallworld.emulators.UnicornEmulator.emulate(
    state, arch=state.arch, mode=state.mode
)

# read the result
print(final_state.eax)
