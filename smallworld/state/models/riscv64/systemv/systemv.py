import struct
import typing

from ..... import emulators, exceptions, platforms
from ...cstd import ArgumentType, CStdModel


class RiscV64SysVModel(CStdModel):
    """Base class for C models using the AArch64 System V ABI"""

    platform = platforms.Platform(
        platforms.Architecture.RISCV64, platforms.Byteorder.LITTLE
    )
    abi = platforms.ABI.SYSTEMV

    _int_sign_mask = 0x80000000
    _int_inv_mask = 0xFFFFFFFF
    _long_sign_mask = 0x8000000000000000
    _long_inv_mask = 0xFFFFFFFFFFFFFFFF
    _long_long_sign_mask = 0x8000000000000000
    _long_long_inv_mask = 0xFFFFFFFFFFFFFFFF

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

    _float_arg_regs = ["fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6"]

    _double_arg_regs = ["fa0", "fa1", "fa2", "fa3", "fa4", "fa5"]

    def _get_argument(
        self, index: int, emulator: emulators.Emulator
    ) -> typing.Union[int, float]:
        if self.argument_types[index] in self._four_byte_types:
            return emulator.read_register(self._four_byte_arg_regs[index])

        elif self.argument_types[index] in self._eight_byte_types:
            return emulator.read_register(self._eight_byte_arg_regs[index])

        elif self.argument_types[index] == ArgumentType.FLOAT:
            intval = emulator.read_register(self._float_arg_regs[index])
            intval &= self._int_inv_mask
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
        val &= self._int_inv_mask
        # riscv64 sign-extends 4-byte ints to fill the register.
        if val & self._int_sign_mask != 0:
            val |= self._int_signext_mask
        emulator.write_register("a0", val)

    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return an eight-byte type"""
        emulator.write_register("a0", val)

    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a float"""
        data = struct.pack("<f", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("fa0", intval)

    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a double"""
        data = struct.pack("<d", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("fa0", intval)
