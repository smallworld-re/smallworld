import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_32, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
filename = (
    __file__.replace(".py", ".pe")
    .replace(".angr", "")
    .replace(".panda", "")
    .replace(".pcode", "")
)
with open(filename, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_pe(f, platform=platform)
    machine.add(code)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
machine.add(stack)

stack.push_integer(0x10101010, 4, None)
cpu.esp.set(stack.get_pointer())


# Configure _main model
class InitModel(smallworld.state.models.Model):
    name = "___main"
    platform = platform
    abi = smallworld.platforms.ABI.NONE

    def model(self, emulator: smallworld.emulators.Emulator) -> None:
        # Return
        pass


init = InitModel(code.address + 0x1550)
machine.add(init)


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
        p = emulator.read_register("esp") + 4
        s = int.from_bytes(emulator.read_memory(p, 4), "little")
        v = b""
        print(f"Reading string at {hex(s)}")
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


puts = PutsModel(0x10000000)
code.update_import("api-ms-win-crt-stdio-l1-1-0.dll", "puts", puts._address)
machine.add(puts)

# Set entrypoint to "main"
cpu.eip.set(code.address + 0x1000)

# Emulate
emulator = smallworld.emulators.PandaEmulator(platform)
emulator.add_exit_point(code.address + 0x102E)
final_machine = machine.emulate(emulator)
