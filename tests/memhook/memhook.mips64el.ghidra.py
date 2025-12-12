import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.MIPS64, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
filename = (
    __file__.replace(".py", ".elf")
    .replace(".angr", "")
    .replace(".ghidra", "")
    .replace(".pcode", "")
)

with open(filename, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf(f, platform=platform)
    machine.add(code)

# Set entrypoint from the ELF
entrypoint = code.get_symbol_value("main")
cpu.pc.set(entrypoint)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x8000, 0x4000)
machine.add(stack)

# Push a return address onto the stack
stack.push_integer(0xFFFFFFFF, 8, "fake return address")

# Configure the stack pointer
sp = stack.get_pointer()
cpu.sp.set(sp)


class FooModel(smallworld.state.models.mmio.MemoryMappedModel):
    def __init__(self, name, address, size):
        self.name = name
        super().__init__(address, size)

    def on_read(
        self,
        emu: smallworld.emulators.Emulator,
        addr: int,
        size: int,
        content: bytes,
    ) -> bytes:
        print(f"{self.name}: read {size} bytes at {hex(addr)}")
        return content

    def on_write(
        self,
        emu: smallworld.emulators.Emulator,
        addr: int,
        size: int,
        value: bytes,
    ) -> None:
        print(f"{self.name}: write {size} bytes at {hex(addr)}")


# Ensure that the entire page is mapped
backing = smallworld.state.memory.Memory(0x1000, 0x1000)
machine.add(backing)

foo = FooModel("foo", 0x1000, 8)
machine.add(foo)

bar = FooModel("bar", 0x100C, 8)
machine.add(bar)

baz = FooModel("baz", 0x101C, 8)
machine.add(baz)

qux = FooModel("qux", 0x1034, 1)
machine.add(qux)

exit_model = smallworld.state.models.Model.lookup(
    "exit", platform, smallworld.platforms.ABI.SYSTEMV, 0x10000
)
machine.add(exit_model)
code.update_symbol_value("exit", exit_model._address)

# UTTER AND TOTAL MADNESS
# MIPS relies on a "Global Pointer" register
# to find its place in a position-independent binary.
# In MIPS64, this is computed by relying on
# the fact that dynamic function calls use
# the t9 register to store the address of the target function.
#
# The function prologue sets gp to t9 plus a constant,
# creating an address that's... not in the ELF image...?
# Position-independent references then subtract
# larger-than-strictly-necessary offsets
# from gp to compute the desired address.
#
# TL;DR: To call main(), t9 must equal main.
cpu.t9.set(entrypoint)

# Emulate
emulator = smallworld.emulators.GhidraEmulator(platform)
emulator.add_exit_point(code.address + code.get_capacity())
final_machine = machine.emulate(emulator)
