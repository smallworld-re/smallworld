
# let's get all of it
import smallworld 

sw = smallworld.Smallworld(cpu=smallworld.X84_64)

# code is of type bytes
code = open("square.bin", "rb").read()

sw.map(0x1000, code)

sw.entry = 0x1000

# logs hints
sw.analyze()

# we look at hints and see edi was uninitialized and so we fix that in
# one of two ways

# way 1
sw.edi = 0xdeadbeef

# or way 2
rand = initializer.RandomUniformInitializer()
sw.edi = rand.draw()

# which lets us now do a single micro-execution with
final_state = sw.emulate(num_instructions=2,engine=smallworld.unicorn)

# tell me what eax ends up
print(final_state.eax)


