# let's get all of it
import smallworld

# create a small world
sw = smallworld.Smallworld(cpu=smallworld.X84_64)

# note: code is of type bytes
code = open("square.bin", "rb").read()

# map the code into memory at this address
sw.map(0x1000, code)

# indicate the entry point
sw.entry = 0x1000

# analyze the code given that entry point
# output: this will log hints somewhere
sw.analyze()

# Now, we examine those hints and learn that
# edi was uninitialized and so we fix that in
# one of two ways

# way 1 to set edi is a specific value
sw.edi = 0xDEADBEEF

# or way 2 is a random draw from an initializer
rand = initializer.RandomUniformInitializer(seed=0xDEEDBEEB)
sw.edi = rand.draw()

# now we can do a single micro-execution without error
final_state = sw.emulate(num_instructions=2, engine=smallworld.unicorn)

# tell me what eax ends up
print(final_state.eax)
