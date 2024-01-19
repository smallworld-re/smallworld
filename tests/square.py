# let's get all of it
import smallworld.smallworld as sw

# create a small world
smw = sw.Smallworld(config=sw.X86_64())

# note: code is of type bytes
code = open("square.bin", "rb").read()

# map the code into memory at this address
smw.map_code(base=0x1000, entry=0x1000, code=code)

# analyze the code given that entry point
# output: this will log hints somewhere
smw.analyze()

# Now, we examine those hints and learn that
# edi was uninitialized and so we fix that in
# one of two ways

# way 1 to set edi is a specific value
smw.cpu.edi.set(0x4)

# or way 2 is a random draw from an initializer
# rand = initializer.RandomUniformInitializer(seed=0xDEEDBEEB)
# smw.cpu.edi.set(rand.word())

print(smw.cpu.edi)

# now we can do a single micro-execution without error
final_state = smw.emulate(num_instructions=2)

# tell me what eax ends up
print(final_state.eax)

smw.cpu.edi.set(0x2)
print(smw.cpu.edi)
final_state2 = smw.emulate(num_instructions=2)
print(final_state2.eax)
