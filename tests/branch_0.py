# NOTE: you have to get rid of hints file first before
# hinting gets set up. that is, right here.
import logging

from smallworld import analyses, cpus, emulators, initializer, utils

utils.setup_logging(level=logging.INFO)
utils.setup_hinting(verbose=True, stream=True, file="hints.jsonl")

# create a small world
code = emulators.Code.from_filepath("branch.bin", base=0x1000, entry=0x1000)
cpu = cpus.AMD64CPUState()
print(code)

zero = initializer.ZeroInitializer()
cpu.initialize(zero)

# map the code into memory at this address
# cpu.map(code) #(base=0x1000, entry=0x1000, code=code)

# analyze the code given that entry point
# output: this will log hints both to stdout and to the file "hints.jsonl"
# smw.analyze()
module = analyses.InputColorizerAnalysis()
module.run(code, cpu)
