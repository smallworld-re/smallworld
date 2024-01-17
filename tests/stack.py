# let's get all of it
import smallworld

# createa a small world
sw = smallworld.Smallworld(cpu=smallworld.X84_64)

# note: code is of type bytes
code = open("stack.bin", "rb").read()

# map the code into memory at this address
sw.map(0x1000, code)

# indicate entry point
sw.entry = 0x1000

# analyze the code given that entry point
# output: this will log hints somewhere
sw.analyze()

# Next, we examine those hints and learn
# that rdi & rdx & r8 are uninitialized.
# Also program fails bc there's no stack,
# i.e. memory pointed to by rsp doesnt exist

# our next edit:

# we set rdi, rdx, and r8

# rdi, rdx, r8 are args 1, 3, and 5 to this fn
sw.rdi = 0x11111111
sw.rdx = 0x22222222
sw.r8 = 0x33333333

# and create stack in order to set final arg used
stack = smallworld.Stack(where=0x2000, size=0x1000)

# this is the 7th arg to `stack.s`
stack.push(value=0x44444444, size=8)

# map the stack into memory
sw.map(stack)

# set rsp to top of stack
sw.rsp = stack.top()

# now we can do a single micro-execution without error
final_state = sw.emulate(num_instructions=3, engine=smallworld.unicorn)

# read out the answer in rax
print(final_state.rax)
