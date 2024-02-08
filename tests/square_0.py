import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file="hints.jsonl")

# load the code and create a state object
code = smallworld.Code.from_filepath("square.bin", base=0x1000, entry=0x1000)
cpu = smallworld.cpus.AMD64CPUState()

# initialize the state object
zero = smallworld.initializers.ZeroInitializer()
cpu.initialize(zero)

# analyze the code
smallworld.analyze(code, cpu)
