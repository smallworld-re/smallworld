import logging

from smallworld import cpus, emulators, initializer, utils

utils.setup_logging(level=logging.INFO)
utils.setup_hinting(verbose=True, stream=True, file="hints.jsonl")

# load code
code = emulators.Code.from_filepath("stack.bin", base=0x1000, entry=0x1000)

# create a cpu state
cpu = cpus.AMD64CPUState()

# initialize it
zero = initializer.ZeroInitializer()
cpu.initialize(zero)

# run an analysis
utils.analyze(code, cpu)
