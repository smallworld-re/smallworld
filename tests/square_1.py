import logging

import smallworld.smallworld as sw
from smallworld import utils

utils.setup_logging(level=logging.INFO)
utils.setup_hinting(verbose=True, stream=True, file="hints.jsonl")

# create a small world
conf = sw.X86_64()
smw = sw.Smallworld(config=conf)

# NOTE: code is of type bytes
code = open("square.bin", "rb").read()

# map the code into memory at this address
smw.map_code(base=0x1000, entry=0x1000, code=code)

# analysis hints from `square_0.py` told us that edi was an input
# so we can now just run a bunch of micro-executions
# randomizing that value

import random

# just showing off that we can emulate over and over
# with different initial settings
for i in range(10):
    print("---------------------")

    # or way 2 is a random draw from an initializer
    smw.cpu.edi.set(random.randint(1, 100))

    print(smw.cpu.edi)

    # now we can do a single micro-execution without error
    final_state = smw.emulate(num_instructions=2)

    # tell me what eax ends up
    print(final_state.eax)
