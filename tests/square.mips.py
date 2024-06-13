import logging
import sys

import smallworld
import smallworld.cpus

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a state object
state = smallworld.state.CPU.for_arch("mips", "mips32", "big")

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath(
    "square.mips.bin", base=0x1000, entry=0x1000, arch="mips", mode="mips32"
)
state.map(code)
state.pc.value = 0x1000

# set input register
state.a0.value = int(sys.argv[-1])
print(state.a0.value)

# now we can do a single micro-execution without error
final_state = smallworld.emulate(state)

# read the result
print(final_state.v0)
