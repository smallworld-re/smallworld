import logging

import smallworld.smallworld as sw
from smallworld import utils

utils.setup_logging(level=logging.INFO)
utils.setup_hinting(verbose=True, stream=True, file="hints.jsonl")

# createa a small world
conf = sw.X86_64()
cpu = sw.i386CPU(config=conf)

# NOTE: code is of type bytes
code = sw.Code(open("stack.bin", "rb").read(), base=0x1000, entry=0x1000)

# map the code into memory at this address
cpu.map(code)

# analysis from stack_0.py told us
# that rdi & rdx & r8 are uninitialized.
# Also program fails bc there's no stack (invalid memory read of [rsp+8]
# i.e. memory pointed to by rsp doesnt exist
#
# So we turn off the analysis and add the following

# create initial values for
# rdi, rdx, r8 which are are args 1, 3, and 5 to this fn
cpu.rdi.set(0x11111111)
cpu.rdx.set(0x22222222)
cpu.r8.set(0x33333333)

# and create stack in order to set final arg used
stack = sw.Stack(base_addr=0x2000, size=0x1000, config=conf)

# this is the 7th arg to `stack.s`
stack.push(value=0x44444444, size=8)

# map the stack into memory
cpu.map(stack)

# set rsp to top of stack
cpu.rsp.set(stack.base_addr)

# now we can do a single micro-execution without error
final_cpu = smallworld.emulate(cpu, num_instructions=3)

# read out the answer in rax
print(final_cpu.rax)
