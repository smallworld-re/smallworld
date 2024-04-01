import logging
import sys

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(level=logging.INFO)

state = smallworld.cpus.AMD64CPUState()
elf = smallworld.state.ELFImage.from_filepath(sys.argv[1])
state.map(elf)
state.rip.set(elf.entry)

smallworld.analyze(state)
