import logging
import sys

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(level=logging.INFO)


# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

code_offset = 0x1000

# Load code as an elf
code = smallworld.state.memory.code.Executable.from_elf(
    open("strdeobfus2", "rb"), address=code_offset
)

# set some code bounds: ok to execute this code
# NB: addresses here come from objdump or radare or something
fns = [
    range(code_offset+0x129e, code_offset+0x12c6),
    range(code_offset+0x1249, code_offset+0x129d)
]
code.bounds = []
for b in fns:
    code.bounds.append(b)

exit_point = 0x12c6

# isn't this something `code` should know?
data = range(0x4000, 0x4000 + 0x465)

# create a stack (we will be calling fns)
stack = smallworld.state.memory.stack.Stack.for_platform(platform, code.address + code.size + code_offset, 0x5000)

# create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
# setentry point for deobfus_strs
cpu.rip.set(code_offset + 0x129e)
# set stack ptr in cpu

cpu.rsp.set(stack.get_pointer() - 128)


# Create a machine
machine = smallworld.state.Machine()
# add cpu and code to machine
machine.add(cpu)
machine.add(code)
machine.add(stack)
machine.add_exit_point(code_offset + exit_point)

encrypted_data = machine.read_memory(code_offset + data.start, len(data))
with open("encrypted_data", "wb") as ed:
    ed.write(encrypted_data)

import pdb
pdb.set_trace()

emu = smallworld.emulators.UnicornEmulator(platform)
#for new_machine in machine.step(emu):
#    print(f"pc={new_machine.get_cpu().pc.get():x}")

new_machine = machine.emulate(emu)



#import pdb
#pdb.set_trace()


print("Done with deobf_strs.  Writing decrypted data section for you")
decrypted_data = new_machine.read_memory(code_offset + data.start, len(data))
with open("decrypted_data", "wb") as dd:
    dd.write(decrypted_data)


