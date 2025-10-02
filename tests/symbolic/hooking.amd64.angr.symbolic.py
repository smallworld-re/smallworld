import logging
import pathlib

import claripy

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
path = pathlib.Path(__file__)
basename = path.name.split(".")[0]
binfile = path.parent.parent / basename / (basename + ".amd64.bin")
code = smallworld.state.memory.code.Executable.from_filepath(
    binfile.as_posix(), address=0x1000
)
machine.add(code)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x8000, 0x4000)
machine.add(stack)

# Set the instruction pointer to the code entrypoint
cpu.rip.set(code.address)

# Push a return address onto the stack
stack.push_integer(0xFFFFFFFF, 8, "fake return address")

# Configure the stack pointer
sp = stack.get_pointer()
cpu.rsp.set(sp)

in_bytes = None


# Configure gets model
class GetsModel(smallworld.state.models.Model):
    name = "gets"
    platform = platform
    abi = smallworld.platforms.ABI.NONE

    def model(self, emulator: smallworld.emulators.Emulator) -> None:
        global in_bytes
        in_bytes = input().encode("utf-8")
        s = emulator.read_register("rdi")
        v = in_bytes + b"\0"
        try:
            emulator.write_memory_content(s, v)
            emulator.write_memory_label(s, len(v) - 1, "input")
        except:
            raise smallworld.exceptions.AnalysisError(
                f"Failed writing {len(v)} bytes to {hex(s)} "
            )


gets = GetsModel(code.address + 0x2800)
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
        global in_bytes
        s = emulator.read_register("rdi")
        b = emulator.read_memory_symbolic(s, 1)
        v = claripy.BVV(b"")
        while b is not None and (b.symbolic or b.concrete_value != 0):
            v = claripy.Concat(v, b)
            s = s + 1
            b = emulator.read_memory_symbolic(s, 1)
        print(v)

        if not isinstance(emulator, smallworld.emulators.ConstrainedEmulator):
            raise TypeError("What emulator did you use?")
        out_bytes = emulator.eval_atmost(v, 1)[0].to_bytes(len(v) // 8, "big")
        if out_bytes != in_bytes:
            raise ValueError(f"Expected {out_bytes!r}, got {in_bytes!r}")


puts = PutsModel(code.address + 0x2808)
machine.add(puts)


# Emulate
emulator = smallworld.emulators.AngrEmulator(platform)
emulator.enable_linear()
machine.add_exit_point(code.address + code.get_capacity() - 1)
final_machine = machine.emulate(emulator)
