import logging
import sys

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a small world
state = smallworld.cpus.AMD64CPUState()

zero = smallworld.initializers.ZeroInitializer()
state.initialize(zero)

state.rdi.set(int(sys.argv[1]))
code = smallworld.Code.from_filepath("branch.bin", base=0x1000, entry=0x1000)
final_state = smallworld.emulate(code, state)
print(final_state.eax)
