import struct
import typing

from ..... import emulators, exceptions, platforms
from ...cstd import ArgumentType, CStdModel


class ArmHFSysVModel(CStdModel):
    """Base class for C models using the ARM32 GNU EABI

    This is a specific ARM System V ABI.
    It generally applies to ARMv5t or ARMv6.
    """

    platform = platforms.Platform(
        platforms.Architecture.ARM_V7A, platforms.Byteorder.LITTLE
    )
    abi = platforms.ABI.SYSTEMV

    _four_byte_types = {
        ArgumentType.INT,
        ArgumentType.UINT,
        ArgumentType.LONG,
        ArgumentType.ULONG,
        ArgumentType.SIZE_T,
        ArgumentType.SSIZE_T,
        ArgumentType.POINTER,
    }

    _eight_byte_types = {
        ArgumentType.LONGLONG,
        ArgumentType.ULONGLONG,
    }

    _argument_regs = ["r0", "r1", "r2", "r3"]

    _float_arg_regs = ["s0", "s1", "s2", "s3", "s4", "s5"]
    _double_arg_regs = ["d0", "d1", "d2", "d3", "d4", "d5"]

    def __init__(self, address):
        super().__init__(address)
        # - ARM32 allows for four argument registers: r0 - r3.
        #   - 4-byte int arguments take up one register.
        #   - 8-byte int arguments take up two registers, and must start on an even-numbered register.
        #     - Case: func(int a, long long b)
        #       - r0: holds 'a'
        #       - r1: unused
        #       - r2: holds 'b'
        #       - r3: holds 'b'
        # - Further arguments are stored on the stack.
        #   - 4-byte int arguments must be 4-byte aligned
        #   - 8-byte int arguments must be 8-byte aligned
        #   - Case: func(long long a, int b, long long c)
        #       - r0:       holds 'a'
        #       - r1:       holds 'a'
        #       - r2:       holds 'b'
        #       - r3:       unused
        #       - sp[0:8]:  holds 'c'
        #   - Case: func(long long a, long long b, int c, long long d)
        #       - r0:       holds 'a'
        #       - r1:       holds 'a'
        #       - r2:       holds 'b'
        #       - r3:       holds 'b'
        #       - sp[0:4]:  holds 'c'
        #       - sp[4:8]:  unused
        #       - sp[8:16]: holds 'd'
        reg_offset = 0
        stack_offset = 0

        self._on_stack = list()
        self._arg_offset = list()

        for i in range(0, len(self.argument_types)):
            t = self.argument_types[i]
            if t in self._four_byte_types:
                if reg_offset == 4:
                    self._on_stack.append(True)
                    self._arg_offset.append(stack_offset)
                    stack_offset += 4
                else:
                    self._on_stack.append(False)
                    self._arg_offset.append(reg_offset)
                    reg_offset += 1
            elif t in self._eight_byte_types:
                if reg_offset >= 3:
                    reg_offset = 4
                    if stack_offset & 0x4 != 0:
                        stack_offset += 4
                    self._on_stack.append(True)
                    self._arg_offset.append(stack_offset)
                    stack_offset += 8
                else:
                    if reg_offset & 1 != 0:
                        reg_offset += 1
                    self._on_stack.append(False)
                    self._arg_offset.append(reg_offset)
                    reg_offset += 2
            elif t == ArgumentType.FLOAT or t == ArgumentType.DOUBLE:
                continue
            else:
                raise exceptions.ConfigurationError(
                    f"{self.name} argument {i} has unknown type {t}"
                )

    def _get_argument(
        self, index: int, emulator: emulators.Emulator
    ) -> typing.Union[int, float]:
        t = self.argument_types[index]
        on_stack = self._on_stack[index]
        arg_offset = self._arg_offset[index]

        if t in self._four_byte_types:
            if on_stack:
                addr = emulator.read_register("sp") + arg_offset
                data = emulator.read_memory(addr, 4)
                return int.from_bytes(data, "little")
            else:
                return emulator.read_register(f"r{arg_offset}")

        elif t in self._eight_byte_types:
            if on_stack:
                addr = emulator.read_register("sp") + arg_offset
                data = emulator.read_memory(addr, 8)
                return int.from_bytes(data, "little")
            else:
                lo = emulator.read_register(f"r{arg_offset}")
                hi = emulator.read_register(f"r{arg_offset + 1}")
                return (hi << 32) | lo

        elif t == ArgumentType.FLOAT:
            intval = emulator.read_register(self._float_arg_regs[index])
            byteval = intval.to_bytes(4, "little")
            (floatval,) = struct.unpack("<f", byteval)
            return floatval

        elif t == ArgumentType.DOUBLE:
            intval = emulator.read_register(self._double_arg_regs[index])
            byteval = intval.to_bytes(8, "little")
            (floatval,) = struct.unpack("<d", byteval)
            return floatval

        else:
            raise exceptions.ConfigurationError(
                f"{self.name} argument {index} has unknown type {t}"
            )

    def _return_4_byte(self, emulator: emulators.Emulator, val: int) -> None:
        emulator.write_register("r0", val)

    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        lo = val & self._int_mask
        hi = val >> 32 & self._int_mask

        emulator.write_register("r0", lo)
        emulator.write_register("r1", hi)

    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        data = struct.pack("<f", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("s0", intval)

    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        data = struct.pack("<d", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("d0", intval)
