# NOTE: you have to get rid of hints file first before
# hinting gets set up. that is, right here.
import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file="hints.jsonl")

# create a small world
code = smallworld.emulators.Code.from_filepath("branch.bin", base=0x1000, entry=0x1000)
cpu = smallworld.cpus.AMD64CPUState()
print(code)

zero = smallworld.initializers.ZeroInitializer()
cpu.initialize(zero)

smallworld.analyze(code, cpu)
