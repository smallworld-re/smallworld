import logging
import os
import sys
import lief
import smallworld

# Set up logging
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

# Load code as an elf
binfile = "strdeobfus"
code = smallworld.state.memory.code.Executable.from_elf(
    open(binfile, "rb"), address=0
)

# set some code bounds: ok to execute this instructions in these ranges
# NB: addresses here come from objdump or radare or something
fns = [
    range(0x11fe, 0x1226),  # kringle_things
    range(0x11a9, 0x11fd)   # kringle_thing
]
code.bounds = []
for b in fns:
    code.bounds.append(b)

exit_point = 0x1226

# create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)

# create a stack (we will be calling fns)
stack = smallworld.state.memory.stack.Stack.for_platform(platform, code.address + code.size + 0x1000, 0x5000)

# set stack ptr in cpu
cpu.rsp.set(stack.get_pointer() - 128)

# set entry point for emulation as start pc for kringle_things
cpu.rip.set(0x11fe)

# Create a machine
machine = smallworld.state.Machine()
# add cpu and code to machine
machine.add(cpu)
machine.add(code)
machine.add(stack)
machine.add_exit_point(exit_point)

# this should execute code to deobfuscate the data section 
# and return a machine with that readable data in memory
emu = smallworld.emulators.UnicornEmulator(platform)

new_machine = machine.emulate(emu)

print("Done with deobf_strs.  Writing version of binary with decrypted data section for you")

# use lief to be able to know where data section is in memory but
# also to modify elf to have decrypted data section.
elf = lief.ELF.parse(binfile)
ds = elf.get_section(".data")
decrypted_data = new_machine.read_memory(ds.virtual_address, ds.size)
ds.content = list(decrypted_data)
elf.write("strdeobfus2")

# make it executable
os.chmod("strdeobfus2", 0o744)

