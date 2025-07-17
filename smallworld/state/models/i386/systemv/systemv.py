import struct
import typing

from ..... import emulators, exceptions, platforms
from ...cstd import ArgumentType, CStdModel


class I386SysVModel(CStdModel):
    """Base class for C models using the AMD64 System V ABI"""

    platform = platforms.Platform(
        platforms.Architecture.X86_32, platforms.Byteorder.LITTLE
    )
    abi = platforms.ABI.SYSTEMV

    _int_sign_mask = 0x80000000
    _int_inv_mask = 0xFFFFFFFF
    _long_sign_mask = 0x80000000
    _long_inv_mask = 0xFFFFFFFF
    _long_long_sign_mask = 0x8000000000000000
    _long_long_inv_mask = 0xFFFFFFFFFFFFFFFF

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

    def __init__(self, address: int):
        super().__init__(address)
        self._arg_offsets = []

        # Starting argument offset is esp + 4
        # In most functions, you'll see it as esp + 8
        # thanks to the pushed value of ebp.
        offset = 4
        for i in range(0, len(self.argument_types)):
            self._arg_offsets.append(offset)
            if self.argument_types[i] in self._four_byte_types:
                offset += 4
            elif self.argument_types[i] in self._eight_byte_types:
                offset += 8
            elif self.argument_types[i] == ArgumentType.FLOAT:
                offset += 4
            elif self.argument_types[i] == ArgumentType.DOUBLE:
                offset += 8
            else:
                raise exceptions.ConfigurationError(
                    f"{self.name} argument {i + 1} has unknown type {self.argument_types[i]}"
                )

    def _get_argument(
        self,
        index: int,
        kind: ArgumentType,
        emulator: emulators.Emulator,
        absolute: bool = False,
    ) -> typing.Union[int, float]:
        addr = emulator.read_register("esp")
        addr += self._arg_offsets[index]

        if self.argument_types[index] in self._four_byte_types:
            data = emulator.read_memory(addr, 4)
            return int.from_bytes(data, "little")

        elif self.argument_types[index] in self._eight_byte_types:
            data = emulator.read_memory(addr, 8)
            return int.from_bytes(data, "little")

        elif self.argument_types[index] == ArgumentType.FLOAT:
            data = emulator.read_memory(addr, 4)
            (floatval,) = struct.unpack("<f", data)
            return floatval

        elif self.argument_types[index] == ArgumentType.DOUBLE:
            data = emulator.read_memory(addr, 8)
            (floatval,) = struct.unpack("<f", data)
            return floatval

        else:
            raise exceptions.ConfigurationError(
                "Unknown type {self.argument_types[i]} for argument {i + 1} of {self.name"
            )

    def _return_4_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return a four-byte type"""
        emulator.write_register("eax", val)

    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return an eight-byte type"""
        hi = (val >> 32) & self._int_inv_mask
        lo = val & self._int_inv_mask

        emulator.write_register("eax", lo)
        emulator.write_register("edx", hi)

    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a float"""
        raise NotImplementedError("i386 System-V uses x87 registers to return floats")

    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a double"""
        raise NotImplementedError("i386 System-V uses x87 registers to return doubles")
