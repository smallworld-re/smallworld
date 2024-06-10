import logging
import sys

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a state object
state = smallworld.cpus.AMD64CPUState()

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath(
    sys.argv[1], base=0x1000, entry=0x1000, arch="x86_64", format="blob"
)
state.map(code)
state.rip.value = code.entry

# analyze
smallworld.analyze(state)
