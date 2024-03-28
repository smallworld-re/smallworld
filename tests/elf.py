import logging
import sys

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(level=logging.INFO)

with open(sys.argv[1], "rb") as f:
    data = f.read()

state = smallworld.cpus.AMD64CPUState()
entry = smallworld.elf.load_elf(state, data, entry=0x1745)
state.rip.value = entry

smallworld.analyze(state)
