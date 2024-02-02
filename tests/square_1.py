import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file="hints.jsonl")

# create a small world
code = smallworld.Code.from_filepath("square.bin", base=0x1000, entry=0x1000)
cpu = smallworld.cpus.AMD64CPUState()

zero = smallworld.initializers.ZeroInitializer()
cpu.initialize(zero)

# analysis hints from `square_0.py` told us that edi was an input
# so we can now just run a bunch of micro-executions
# randomizing that value

import random

# just showing off that we can emulate over and over
# with different initial settings
for i in range(10):
    print("---------------------")

    # or way 2 is a random draw from an initializers
    cpu.edi.set(random.randint(1, 100))

    print(cpu.edi.get())

    # now we can do a single micro-execution without error
    final_state = smallworld.emulate(code, cpu)

    # tell me what eax ends up
    print(final_state.eax)
