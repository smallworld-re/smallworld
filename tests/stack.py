
# let's get all of it
import smallworld

sw = smallword.Smallworld(cpu=smallword.X84_64)

# code is of type bytes
code = open("stack.bin", "rb").read()

sw.map(0x1000, code)

sw.entry = 0x1000

# logs hints
sw.analyze()

# we look at hints and see 
# rdi & rdx & r8 are uninitialized
# and program fails bc stack not there

# our next edit: 

# we set rdi, rdx, and r8
# and create stack

# concrete version first
sw.rdi = 0x11111111
sw.rdx = 0x22222222
sw.r8 =  0x33333333

stack = smallword.Stack(where=0x2000, size=0x1000)

stack.push(value=0x44444444, size=8)

sw.map(stack)

sw.rsp = stack.top()

# which lets us now do a single micro-execution with
final_state = sw.emulate(num_instructions=3, engine=smallword.unicorn)

# tell me what eax ends up
print(final_state.rax)


