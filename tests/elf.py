import logging
import sys

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(level=logging.INFO)

with open(sys.argv[1], "rb") as f:
    data = f.read()

state = smallworld.cpus.AMD64CPUState()
elf = smallworld.state.ELFImage(data)
state.map(elf)
state.rip.set(elf.entry)

smallworld.analyze(state)
