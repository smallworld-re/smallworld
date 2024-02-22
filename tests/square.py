import logging
import sys

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a state object and initialize it
state = smallworld.cpus.AMD64CPUState()
zero = smallworld.initializers.ZeroInitializer()
state.initialize(zero)

# load and map code into the state
code = smallworld.state.Code.from_filepath("square.bin", base=0x1000, entry=0x1000)
state.map(code)

# set input register
state.edi.set(int(sys.argv[-1]))
print(state.edi.get())

# now we can do a single micro-execution without error
final_state = smallworld.emulate(state)

# read the result
print(final_state.eax)
