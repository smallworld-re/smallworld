import logging
import sys

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a state object
state = smallworld.cpus.AMD64CPUState()

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath("square.bin", base=0x1000, entry=0x1000)
state.map(code)
state.rip.value = 0x1000

# set input register
state.edi.value = int(sys.argv[-1])
print(state.edi.value)

# now we can do a single micro-execution without error
final_state = smallworld.emulate(state)

# read the result
print(final_state.eax)
