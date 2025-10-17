import logging
import math
import typing
from enum import Enum

import smallworld
from smallworld.state.models.cstd import ArgumentType
from smallworld.state.models.funcptr import FunctionPointer
from smallworld.state.models.riscv64.systemv.systemv import RiscV64SysVModel

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.RISCV64, smallworld.platforms.Byteorder.LITTLE
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
    code = smallworld.state.memory.code.Executable.from_elf(
        f, platform=platform, address=0x400000
    )
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

# Configure the heap
heap = smallworld.state.memory.heap.BumpAllocator(0x20000, 0x1000)
machine.add(heap)


class TestStage(Enum):
    INIT = 0
    VOID = 1
    INT32 = 2
    UINT32 = 3
    INT64 = 4
    UINT64 = 5
    FLOAT = 6
    DOUBLE = 7


class TestModel(RiscV64SysVModel):
    name = "caller"
    platform = platform
    abi = smallworld.platforms.ABI.SYSTEMV
    return_addr = 0
    stage = TestStage.INIT

    def fail(self, emulator: smallworld.emulators.Emulator) -> None:
        print(f"TEST FAILED: {self.stage}")
        self.set_return_address(emulator, self.return_addr)
        self.set_return_value(emulator, 1)
        self.skip_return = False

    def model(self, emulator: smallworld.emulators.Emulator) -> None:
        match (self.stage):
            case TestStage.INIT:
                self.return_addr = self.get_return_address(emulator)

                # populate model's types
                self.set_argument_types(
                    [
                        ArgumentType.POINTER,
                        ArgumentType.POINTER,
                        ArgumentType.POINTER,
                        ArgumentType.POINTER,
                        ArgumentType.POINTER,
                        ArgumentType.POINTER,
                        ArgumentType.POINTER,
                    ]
                )
                self.return_type = ArgumentType.INT

                # collect args
                self.test_void = typing.cast(int, self.get_arg1(emulator))
                self.test_int32 = typing.cast(int, self.get_arg2(emulator))
                self.test_uint32 = typing.cast(int, self.get_arg3(emulator))
                self.test_int64 = typing.cast(int, self.get_arg4(emulator))
                self.test_uint64 = typing.cast(int, self.get_arg5(emulator))
                self.test_float = typing.cast(int, self.get_arg6(emulator))
                self.test_double = typing.cast(
                    int,
                    self.get_argument(6, self.argument_types[6], emulator),
                )
                assert isinstance(self.test_void, int)
                assert isinstance(self.test_int32, int)
                assert isinstance(self.test_uint32, int)
                assert isinstance(self.test_int64, int)
                assert isinstance(self.test_uint64, int)
                assert isinstance(self.test_float, int)
                assert isinstance(self.test_double, int)

                # test void
                self.test_void_ptr = FunctionPointer(
                    self.test_void, [], ArgumentType.VOID, platform
                )
                self.test_void_ptr.call(emulator, [], self._address)
                self.stage = TestStage.VOID
                self.skip_return = True

            case TestStage.VOID:
                print(f"TEST PASSED: {self.stage}")

                # test int32
                self.test_int32_ptr = FunctionPointer(
                    self.test_int32, [ArgumentType.INT], ArgumentType.INT, platform
                )
                self.test_int32_ptr.call(emulator, [-12345], self._address)
                self.stage = TestStage.INT32

            case TestStage.INT32:
                ret = self.test_int32_ptr.get_return_value(emulator)
                print(ret)
                if ret != -12345:
                    return self.fail(emulator)
                print(f"TEST PASSED: {self.stage}")

                # test uint32
                self.test_uint32_ptr = FunctionPointer(
                    self.test_uint32, [ArgumentType.UINT], ArgumentType.UINT, platform
                )
                self.test_uint32_ptr.call(emulator, [12345], self._address)
                self.stage = TestStage.UINT32

            case TestStage.UINT32:
                ret = self.test_uint32_ptr.get_return_value(emulator)
                if ret != 12345:
                    return self.fail(emulator)
                print(f"TEST PASSED: {self.stage}")

                # test int64
                self.test_int64_ptr = FunctionPointer(
                    self.test_int64,
                    [ArgumentType.LONGLONG],
                    ArgumentType.LONGLONG,
                    platform,
                )
                self.test_int64_ptr.call(emulator, [-8589934592], self._address)
                self.stage = TestStage.INT64

            case TestStage.INT64:
                ret = self.test_int64_ptr.get_return_value(emulator)
                if ret != -8589934592:
                    return self.fail(emulator)
                print(f"TEST PASSED: {self.stage}")

                # test uint64
                self.test_uint64_ptr = FunctionPointer(
                    self.test_uint64,
                    [ArgumentType.ULONGLONG],
                    ArgumentType.ULONGLONG,
                    platform,
                )
                self.test_uint64_ptr.call(emulator, [8589934592], self._address)
                self.stage = TestStage.UINT64

            case TestStage.UINT64:
                ret = self.test_uint64_ptr.get_return_value(emulator)
                if ret != 8589934592:
                    return self.fail(emulator)
                print(f"TEST PASSED: {self.stage}")

                # test float
                self.test_float_ptr = FunctionPointer(
                    self.test_float, [ArgumentType.FLOAT], ArgumentType.FLOAT, platform
                )
                self.test_float_ptr.call(emulator, [math.pi], self._address)
                self.stage = TestStage.FLOAT

            case TestStage.FLOAT:
                ret = self.test_float_ptr.get_return_value(emulator)
                if not math.isclose(ret, math.pi, abs_tol=1e-07):
                    return self.fail(emulator)
                print(f"TEST PASSED: {self.stage}")

                # test double
                self.test_double_ptr = FunctionPointer(
                    self.test_double,
                    [ArgumentType.DOUBLE],
                    ArgumentType.DOUBLE,
                    platform,
                )
                self.test_double_ptr.call(emulator, [math.pi], self._address)
                self.stage = TestStage.DOUBLE

            case TestStage.DOUBLE:
                ret = self.test_double_ptr.get_return_value(emulator)
                if math.isclose(ret, math.pi):
                    return self.fail(emulator)
                print(f"TEST PASSED: {self.stage}")

                # exit successfully
                self.set_return_address(emulator, self.return_addr)
                self.set_return_value(emulator, 0)
                self.skip_return = False


test_addr = code.get_symbol_value("test")
test_model = TestModel(test_addr)
machine.add(test_model)


# Create a type of exception only I will generate
class FailExitException(Exception):
    pass


# We signal failure qsort by dereferencing 0xdead.
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
emulator = smallworld.emulators.GhidraEmulator(platform)
emulator.add_exit_point(entrypoint + 0x1000)
try:
    machine.emulate(emulator)
    raise Exception("Did not exit as expected")
except FailExitException:
    pass
