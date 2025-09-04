import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.ARM_V5T, smallworld.platforms.Byteorder.LITTLE
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
    .replace(".ghidra", "")
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


foo = FooModel("foo", 0x1000, 8)
machine.add(foo)

bar = FooModel("bar", 0x1010, 8)
machine.add(bar)

baz = FooModel("baz", 0x1020, 8)
machine.add(baz)

qux = FooModel("qux", 0x1034, 1)
machine.add(qux)

exit_model = smallworld.state.models.Model.lookup(
    "exit", platform, smallworld.platforms.ABI.SYSTEMV, 0x10000
)
machine.add(exit_model)
code.update_symbol_value("exit", exit_model._address)

# Emulate
emulator = smallworld.emulators.GhidraEmulator(platform)
emulator.add_exit_point(code.address + code.get_capacity())
final_machine = machine.emulate(emulator)
