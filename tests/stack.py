import logging

import smallworld

smallworld.setup_logging(level=logging.INFO)
smallworld.setup_hinting(verbose=True, stream=True, file=None)

# create a state object and initialize it
state = smallworld.cpus.AMD64CPUState()
zero = smallworld.initializers.ZeroInitializer()
state.initialize(zero)

# load and map code into the state
code = smallworld.state.Code.from_filepath("stack.bin", base=0x1000, entry=0x1000)
state.map(code)

# initialize some values
state.rdi.set(0x11111111)
state.rdx.set(0x22222222)
state.r8.set(0x33333333)

# create a stack and push a value
stack = smallworld.state.Stack(address=0x2000, size=0x1000)
stack.push(value=0x44444444, size=8)

# map the stack into memory
state.map(stack)

# set the stack pointer
state.rsp.set(stack.address)

# emulate
final = smallworld.emulate(state)

# read out the final state
print(final.rax)
