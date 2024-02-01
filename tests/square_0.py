# NOTE: you have to get rid of hints file first before
# hinting gets set up. that is, right here.

import logging

from smallworld import cpus, emulators, initializers, utils

utils.setup_logging(level=logging.INFO)
utils.setup_hinting(verbose=True, stream=True, file="hints.jsonl")

# create a small world
code = emulators.Code.from_filepath("square.bin", base=0x1000, entry=0x1000)
cpu = cpus.AMD64CPUState()

zero = initializers.ZeroInitializer()
cpu.initialize(zero)

# analyze the code given that entry point
# output: this will log hints both to stdout and to the file "hints.jsonl"
utils.analyze(code, cpu)
