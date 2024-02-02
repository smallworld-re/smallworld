# NOTE: you have to get rid of hints file first before
# hinting gets set up. that is, right here.
import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file="hints.jsonl")

# create a small world
code = smallworld.Code.from_filepath("branch.bin", base=0x1000, entry=0x1000)
cpu = smallworld.cpus.AMD64CPUState()

zero = smallworld.initializers.ZeroInitializer()
cpu.initialize(zero)

# analysis of branch_0.py gives us two InputUseHints These tell us tha
# two inputs (eax_0 and rdi_0) are directly used in two different
# instructions.
#
# 1. eax_0 is used in pc=0x1000 "xor eax, eax"
#    -- ok that's useless which should be knowable given that
#       instruction pattern is same as eax=0
#
# 2. rdi_0 is used in pc=0x1002 "cmp rdi, 0x64"
#    -- ok that's helpful. Very naively, we can use it to arrange
#       for 3 micro-executions with rdi_0 = [0x63,0x64,0x65],
#       i.e., less than, equal to, and greater than 0x64

rdi_vals = [0x63, 0x64, 0x65]

for rdi_val in rdi_vals:
    print("-------------------------")
    cpu.rdi.set(rdi_val)
    print(cpu.rdi.get())

    final_state = smallworld.emulate(code, cpu)

    print(final_state.eax)
