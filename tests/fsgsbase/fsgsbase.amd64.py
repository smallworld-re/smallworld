import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
code = smallworld.state.memory.code.Executable.from_filepath(
    __file__.replace(".py", ".bin")
    .replace(".angr", "")
    .replace(".panda", "")
    .replace(".pcode", ""),
    address=0x1000,
)
machine.add(code)

# Set the instruction pointer to the code entrypoint
cpu.pc.set(code.address)

# set up fs memory segment and fsbase msr
fs_mem_base = 0x2000
fs_mem_size = 0x100
fsm = smallworld.state.memory.Memory(fs_mem_base, fs_mem_size)
the_bytes = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
#             0123456789abcdef0123456789abcdef0123456789abcdef
#                                                     ^ this is fs:[0x28]
fsm.write_bytes(fs_mem_base, the_bytes, smallworld.platforms.Byteorder.LITTLE)

cpu.fsbase.set(fs_mem_base)

# set up gs memory segment and gsbase msr
gs_mem_base = 0x3000
gs_mem_size = 0x100
gsm = smallworld.state.memory.Memory(gs_mem_base, gs_mem_size)
the_bytes = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
#             0123456789abcdef0123456789abcdef0123456789abcdef
#                                ^ this is gs:[0x13]
gsm.write_bytes(gs_mem_base, the_bytes, smallworld.platforms.Byteorder.LITTLE)

cpu.gsbase.set(gs_mem_base)

# NOTE!  If you set fs or gs registers then all of this fails.  Not
# sure why.  This is even if you set them to 0.  Which is odd, since
# if you read their values after emulating, they both appear to be
# zero.
#
# cpu.fs.set(0) # <- don't do this!
# cpu.gs.set(0) # <- and don't do this!

machine.add(fsm)
machine.add(gsm)

machine.add_exit_point(cpu.rip.get() + code.get_capacity())

emulator = smallworld.emulators.UnicornEmulator(platform)

machine.apply(emulator)

# Emulate
final_machine = machine.emulate(emulator)
cpu = final_machine.get_cpu()


def prc(lab, v, sz):
    print(lab + ": ", end="")
    for i in range(sz):
        a = v & 0xFF
        print(chr(a), end="")
        v = v >> 8
    print("")


rax = cpu.rax.get()
prc("rax", rax, 8)
lsb_rax = rax & 0xFF
ind_fs = the_bytes.index(lsb_rax)

rbx = cpu.rbx.get()
prc("rbx", rbx, 8)
lsb_rbx = rbx & 0xFF
ind_gs = the_bytes.index(lsb_rbx)

print(f"Here's where in fs segment lsb of rax is: {ind_fs}.", end="")
if ind_fs == 0x28:
    print(" ... which is correct.  Looks like fs:[0x28] address is working properly.")
else:
    print(" ... which is incorrect. Looks like fs:[0x28] address is not working right.")


print(f"Here's where in gs segment lsb of rbx is: {ind_gs}.", end="")
if ind_gs == 0x13:
    print(" ... which is correct.  Looks like gs:[0x13] address is working properly.")
else:
    print(" ... which is incorrect. Looks like gs:[0x13] address is not working right.")
