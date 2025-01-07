import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=True, verbose=True)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.MIPS32, smallworld.platforms.Byteorder.BIG
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
filename = __file__.replace(".py", ".elf").replace(".angr", "")
with open(filename, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf(f, platform=platform)
    machine.add(code)

# Set the entrypoint to the address of "main"
entrypoint = code.get_symbol_value("main")
print(f"Entrypoint {hex(entrypoint)}")
cpu.pc.set(entrypoint)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x8000, 0x4000)
machine.add(stack)

# Push a return address onto the stack
stack.push_integer(0xFFFFFFFF, 4, "Arg Slot 2")
stack.push_integer(0xFFFFFFFF, 4, "Arg Slot 1")

# Configure the stack pointer
sp = stack.get_pointer()
cpu.sp.set(sp)


# Configure puts model
class PutsModel(smallworld.state.models.Model):
    name = "puts"
    platform = platform
    abi = smallworld.platforms.ABI.NONE

    def model(self, emulator: smallworld.emulators.Emulator) -> None:
        # Reading a block of memory from angr will fail,
        # since values beyond the string buffer's bounds
        # are guaranteed to be symbolic.
        #
        # Thus, we must step one byte at a time.
        s = emulator.read_register("a0")
        v = b""
        try:
            b = emulator.read_memory_content(s, 1)
        except smallworld.exceptions.SymbolicValueError:
            b = None
        while b is not None and b != b"\x00":
            v = v + b
            s = s + 1
            try:
                b = emulator.read_memory_content(s, 1)
            except smallworld.exceptions.SymbolicValueError:
                b = None
        if b is None:
            raise smallworld.exceptions.SymbolicValueError(f"Symbolic byte at {hex(s)}")
        print(v)


puts = PutsModel(0x10000)
machine.add(puts)

# Relocate puts
code.update_symbol_value("puts", puts._address)

# Emulate
emulator = smallworld.emulators.UnicornEmulator(platform)
emulator.add_exit_point(entrypoint + 88)
machine.emulate(emulator)
