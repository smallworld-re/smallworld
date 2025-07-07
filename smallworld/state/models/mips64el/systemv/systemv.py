import struct
import typing

from ..... import emulators, exceptions, platforms
from ...cstd import ArgumentType, CStdModel


class MIPS64ELSysVModel(CStdModel):
    """Base class for C models using the AArch64 System V ABI"""

    platform = platforms.Platform(
        platforms.Architecture.MIPS64, platforms.Byteorder.LITTLE
    )
    abi = platforms.ABI.SYSTEMV

    _four_byte_types = {ArgumentType.INT, ArgumentType.UINT}

    _eight_byte_types = {
        ArgumentType.LONG,
        ArgumentType.ULONG,
        ArgumentType.LONGLONG,
        ArgumentType.ULONGLONG,
        ArgumentType.SIZE_T,
        ArgumentType.SSIZE_T,
        ArgumentType.POINTER,
    }

    _four_byte_arg_regs = ["a0", "a1", "a2", "a3", "a4", "a5"]

    _eight_byte_arg_regs = [
        "a0",
        "a1",
        "a2",
        "a3",
        "a4",
        "a5",
    ]

    _float_arg_regs = [
        "f12",
        "f13",
        "f14",
        "f15",
        "f16",
        "f17",
    ]

    _double_arg_regs = [
        "f12",
        "f13",
        "f14",
        "f15",
        "f16",
        "f17",
    ]

    def _get_argument(
        self, index: int, emulator: emulators.Emulator
    ) -> typing.Union[int, float]:
        if self.argument_types[index] in self._four_byte_types:
            return (
                emulator.read_register(self._four_byte_arg_regs[index]) & self._int_mask
            )

        elif self.argument_types[index] in self._eight_byte_types:
            return emulator.read_register(self._eight_byte_arg_regs[index])

        elif self.argument_types[index] == ArgumentType.FLOAT:
            intval = emulator.read_register(self._float_arg_regs[index])
            intval &= self._int_mask
            byteval = intval.to_bytes(4, "little")
            (floatval,) = struct.unpack("<f", byteval)
            return floatval

        elif self.argument_types[index] == ArgumentType.DOUBLE:
            intval = emulator.read_register(self._double_arg_regs[index])
            byteval = intval.to_bytes(8, "little")
            (floatval,) = struct.unpack("<d", byteval)
            return floatval

        else:
            raise exceptions.ConfigurationError(
                "Unknown type {self.argument_types[i]} for argument {i + 1} of {self.name"
            )

    def _return_4_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return a four-byte type"""
        val &= self._int_mask
        if val & self._int_sign_mask != 0:
            val |= self._int_signext_mask
        emulator.write_register("v0", val)

    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return an eight-byte type"""
        emulator.write_register("v0", val)

    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a float"""
        data = struct.pack("<f", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("f0", intval)

    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a double"""
        data = struct.pack("<d", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("f0", intval)
