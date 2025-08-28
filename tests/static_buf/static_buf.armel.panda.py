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
cpu.pc.set(code.address + 4)

# Push a return address onto the stack
stack.push_integer(0xFFFFFFFF, 8, "fake return address")

# Configure the stack pointer
sp = stack.get_pointer()
cpu.sp.set(sp)


# Configure puts model
class FoobarModel(smallworld.state.models.Model):
    name = "foobar"
    platform = platform
    abi = smallworld.platforms.ABI.NONE

    static_space_required = 4

    def model(self, emulator: smallworld.emulators.Emulator) -> None:
        # Reading a block of memory from angr will fail,
        # since values beyond the string buffer's bounds
        # are guaranteed to be symbolic.
        #
        # Thus, we must step one byte at a time.
        assert self.static_buffer_address is not None

        if platform.byteorder == smallworld.platforms.Byteorder.LITTLE:
            data = 0x04A1.to_bytes(4, "little")
        elif platform.byteorder == smallworld.platforms.Byteorder.BIG:
            data = 0x04A1.to_bytes(4, "big")
        emulator.write_memory(self.static_buffer_address, data)
        emulator.write_register("r0", self.static_buffer_address)


foobar = FoobarModel(0x1000)
foobar.static_buffer_address = 0x10000
machine.add(foobar)

# Emulate
emulator = smallworld.emulators.PandaEmulator(platform)
emulator.add_exit_point(code.address + code.get_capacity())
final_machine = machine.emulate(emulator)

print(final_machine.get_cpu().r0)
