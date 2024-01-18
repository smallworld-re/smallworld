# let's get all of it

import smallworld.smallworld as sw

from smallworld import cpus, initializer

import pdb
pdb.set_trace()

# create a small world
smw = sw.Smallworld(cpu=cpus.AMD64CPUState())

# note: code is of type bytes
code = open("square.bin", "rb").read()

# map the code into memory at this address
smw.map(0x1000, code)

# indicate the entry point
smw.entry = 0x1000

# analyze the code given that entry point
# output: this will log hints somewhere
smw.analyze()

# Now, we examine those hints and learn that
# edi was uninitialized and so we fix that in
# one of two ways

# way 1 to set edi is a specific value
smw.edi = 0xDEADBEEF

# or way 2 is a random draw from an initializer
rand = smallworld.initializer.RandomUniformInitializer(seed=0xDEEDBEEB)
smw.edi = rand.draw()

# now we can do a single micro-execution without error
final_state = smw.emulate(num_instructions=2, engine=smallworld.unicorn)

# tell me what eax ends up
print(final_state.eax)
