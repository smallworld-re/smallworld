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
filename = (
    __file__.replace(".py", ".elf")
    .replace(".angr", "")
    .replace(".panda", "")
    .replace(".pcode", "")
)
with open(filename, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf(f, platform=platform)
    machine.add(code)

# Set the entrypoint to the address of "main"
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


class Foo(smallworld.state.models.mips.systemv.systemv.MIPSSysVModel):
    name = "foo"

    argument_types = [
        smallworld.state.models.cstd.ArgumentType.ULONGLONG,
        smallworld.state.models.cstd.ArgumentType.UINT,
        smallworld.state.models.cstd.ArgumentType.ULONGLONG,
        smallworld.state.models.cstd.ArgumentType.UINT,
        smallworld.state.models.cstd.ArgumentType.ULONGLONG,
    ]

    return_type = smallworld.state.models.cstd.ArgumentType.VOID

    def model(self, emulator) -> None:
        arg1_expected = 0x123456789ABCDEF
        arg1_actual = self.get_arg1(emulator)
        assert isinstance(arg1_actual, int)
        if arg1_actual != arg1_expected:
            raise Exception(
                f"arg1: Expected {hex(arg1_expected)}, got {hex(arg1_actual)}"
            )

        arg2_expected = 0x87654321
        arg2_actual = self.get_arg2(emulator)
        assert isinstance(arg2_actual, int)
        if arg2_actual != arg2_expected:
            raise Exception(
                f"arg2: Expected {hex(arg2_expected)}, got {hex(arg2_actual)}"
            )

        arg3_expected = 0x08192A3B4C5D6E7F
        arg3_actual = self.get_arg3(emulator)
        assert isinstance(arg3_actual, int)
        if arg3_actual != arg3_expected:
            raise Exception(
                f"arg3: Expected {hex(arg3_expected)}, got {hex(arg3_actual)}"
            )

        arg5_expected = 0xF0E1D2C3B4A59687
        arg5_actual = self.get_arg5(emulator)
        assert isinstance(arg5_actual, int)
        if arg5_actual != arg5_expected:
            raise Exception(
                f"arg5: Expected {hex(arg5_expected)}, got {hex(arg5_actual)}"
            )

        varargs = self.get_varargs()

        # Skip argument six
        varargs.get_next_argument(
            smallworld.state.models.cstd.ArgumentType.ULONGLONG, emulator
        )

        arg7_expected = 0xC001D00D
        arg7_actual = varargs.get_next_argument(
            smallworld.state.models.cstd.ArgumentType.UINT, emulator
        )
        assert isinstance(arg7_actual, int)
        if arg7_actual != arg7_expected:
            raise Exception(
                f"arg7: Expected {hex(arg7_expected)}, got {hex(arg7_actual)}"
            )

        # Skip argument eight
        varargs.get_next_argument(
            smallworld.state.models.cstd.ArgumentType.UINT, emulator
        )

        arg9_expected = 0x1337BEEF
        arg9_actual = varargs.get_next_argument(
            smallworld.state.models.cstd.ArgumentType.ULONGLONG, emulator
        )
        assert isinstance(arg9_actual, int)
        if arg9_actual != arg9_expected:
            raise Exception(
                f"arg9: Expected {hex(arg9_expected)}, got {hex(arg9_actual)}"
            )


foo_addr = code.get_symbol_value("foo")

foo_model = smallworld.state.models.Model.lookup(
    "foo", platform, smallworld.platforms.ABI.SYSTEMV, foo_addr
)
machine.add(foo_model)
foo_model.allow_imprecise = True


class Bar(smallworld.state.models.mips.systemv.systemv.MIPSSysVModel):
    name = "bar"
    argument_types = [
        smallworld.state.models.cstd.ArgumentType.UINT,
        smallworld.state.models.cstd.ArgumentType.FLOAT,
        smallworld.state.models.cstd.ArgumentType.DOUBLE,
    ]

    return_type = smallworld.state.models.cstd.ArgumentType.VOID

    def model(self, emulator) -> None:
        arg2_expected = 0.25
        arg2_actual = self.get_arg2(emulator)
        assert isinstance(arg2_actual, float)
        if arg2_actual != arg2_expected:
            raise Exception(f"arg2: Expected {arg2_expected}, got {arg2_actual}")

        arg3_expected = 0.21
        arg3_actual = self.get_arg3(emulator)
        assert isinstance(arg3_actual, float)
        if arg3_actual != arg3_expected:
            raise Exception(f"arg3: Expected {arg3_expected}, got {arg3_actual}")


bar_addr = code.get_symbol_value("bar")
bar = Bar(bar_addr)

bar_model = smallworld.state.models.Model.lookup(
    "bar", platform, smallworld.platforms.ABI.SYSTEMV, bar_addr
)
machine.add(bar_model)
bar_model.allow_imprecise = True


# Create a type of exception only I will generate
class FailExitException(Exception):
    pass


# We signal failure exits by dereferencing 0xdead.
# Catch the dereference
class DeadModel(smallworld.state.models.mmio.MemoryMappedModel):
    def __init__(self):
        super().__init__(0xDEAD, 1)

    def on_read(
        self, emu: smallworld.emulators.Emulator, addr: int, size: int, content: bytes
    ) -> bytes:
        raise FailExitException()

    def on_write(
        self, emu: smallworld.emulators.Emulator, addr: int, size: int, value: bytes
    ) -> None:
        pass


dead = DeadModel()
machine.add(dead)

# Emulate
emulator = smallworld.emulators.UnicornEmulator(platform)
emulator.add_exit_point(entrypoint + 0x1000)

try:
    machine.emulate(emulator)
    raise Exception("Exit point never reached")

except FailExitException:
    pass
