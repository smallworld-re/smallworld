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
code = smallworld.state.memory.code.Executable.from_filepath(
    __file__.replace(".py", ".bin")
    .replace(".angr", "")
    .replace(".panda", "")
    .replace(".pcode", ""),
    address=0x1000,
)
machine.add(code)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
machine.add(stack)

# Set the instruction pointer to the code entrypoint
cpu.eip.set(code.address + 2)

# Push a return address onto the stack
stack.push_integer(0xFFFFFFFF, 4, "fake return address")

# Configure the stack pointer
sp = stack.get_pointer()
cpu.esp.set(sp)


# Configure gets model
class GetsModel(smallworld.state.models.Model):
    name = "gets"
    platform = platform
    abi = smallworld.platforms.ABI.NONE

    def model(self, emulator: smallworld.emulators.Emulator) -> None:
        a = emulator.read_register("esp")
        s = int.from_bytes(emulator.read_memory(a + 4, 4), "little")
        v = input().encode("utf-8") + b"\0"
        try:
            emulator.write_memory_content(s, v)
        except:
            raise smallworld.exceptions.AnalysisError(
                f"Failed writing {len(v)} bytes to {hex(s)} "
            )


gets = GetsModel(0x1000)
machine.add(gets)


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
        a = emulator.read_register("esp")
        s = int.from_bytes(emulator.read_memory(a + 4, 4), "little")
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


puts = PutsModel(0x1001)
machine.add(puts)

# Emulate
emulator = smallworld.emulators.UnicornEmulator(platform)
emulator.add_exit_point(code.address + code.get_capacity())
final_machine = machine.emulate(emulator)
