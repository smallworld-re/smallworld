import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a state object
state = smallworld.cpus.AMD64CPUState()

# load and map code into the state and set ip
code = smallworld.state.Code.from_filepath("stack.bin", base=0x1000, entry=0x1000)
state.map(code)
state.rip.value = code.entry

# initialize some values
state.rdi.value = 0x11111111
state.rdx.value = 0x22222222
state.r8.value = 0x33333333

# create a stack and push a value
stack = smallworld.state.Stack(address=0x2000, size=0x1000)
stack.push(value=0xFFFFFFFF, size=8, type=int, label="fake return address")
stack.push(value=0x44444444, size=8, type=int, label="7th argument")

# map the stack into memory
state.map(stack)

# set the stack pointer
state.rsp.value = stack.address

# emulate
final = smallworld.emulate(state)

# read out the final state
print(final.rax)
