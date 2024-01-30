import logging

from smallworld import cpus, executor, initializer, state, utils

utils.setup_logging(level=logging.INFO)
utils.setup_hinting(verbose=True, stream=True, file="hints.jsonl")

# load code
code = executor.Code.from_filepath("stack.bin", base=0x1000, entry=0x1000)

# create a cpu state
cpu = cpus.AMD64CPUState()

# initialize it
zero = initializer.ZeroInitializer()
cpu.initialize(zero)

# initialize some values
cpu.rdi.set(0x11111111)
cpu.rdx.set(0x22222222)
cpu.r8.set(0x33333333)

# create a stack and push a value
stack = state.Stack(address=0x2000, size=0x1000)
stack.push(value=0x44444444, size=8)

# map the stack into memory
cpu.map(stack)

# set the stack pointer
cpu.rsp.set(stack.address)

# run an analysis
utils.analyze(code, cpu)

# emulate
final = utils.emulate(code, cpu)

# read out the final state
print(final.rax)
