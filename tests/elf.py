import logging
import sys

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(level=logging.INFO)

state = smallworld.state.CPU.for_arch("x86", "64", "little")
elf = smallworld.state.ELFImage.from_filepath(sys.argv[1])
state.map(elf)
state.rip.value = elf.entry

smallworld.analyze(state)
