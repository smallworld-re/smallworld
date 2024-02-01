import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file="hints.jsonl")

# load code
code = smallworld.emulators.Code.from_filepath("stack.bin", base=0x1000, entry=0x1000)

# create a cpu state
cpu = smallworld.cpus.AMD64CPUState()

# initialize it
zero = smallworld.initializers.ZeroInitializer()
cpu.initialize(zero)

# run an analysis
smallworld.analyze(code, cpu)
