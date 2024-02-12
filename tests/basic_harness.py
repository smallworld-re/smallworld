import logging
import sys

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

state = smallworld.cpus.AMD64CPUState()
zero = smallworld.initializers.ZeroInitializer()
state.initialize(zero)


code = smallworld.Code.from_filepath(sys.argv[1], base=0x1000, entry=0x1000)
smallworld.analyze(code, state)
