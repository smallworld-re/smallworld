import logging
import sys

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# load the code and create a state object
code = smallworld.Code.from_filepath("square.bin", base=0x1000, entry=0x1000)
cpu = smallworld.cpus.AMD64CPUState()

# initialize the state object
zero = smallworld.initializers.ZeroInitializer()
cpu.initialize(zero)

cpu.edi.set(int(sys.argv[-1]))

print(cpu.edi.get())

# now we can do a single micro-execution without error
final_state = smallworld.emulate(code, cpu)

# read the result
print(final_state.eax)
