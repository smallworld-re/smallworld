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
code = smallworld.state.Code.from_filepath(sys.argv[1], base=0x1000, entry=0x1000)
state.map(code)

# analyze
smallworld.analyze(state)
