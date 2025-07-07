import struct
import typing

from ..... import emulators, exceptions, platforms
from ...cstd import ArgumentType, CStdModel


class AMD64SysVModel(CStdModel):
    """Base class for C models using the AMD64 System V ABI"""

    platform = platforms.Platform(
        platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
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

    _four_byte_arg_regs = ["edi", "esi", "edx", "ecx", "r8d", "r9d"]

    _eight_byte_arg_regs = [
        "rdi",
        "rsi",
        "rdx",
        "rcx",
        "r8",
        "r9",
    ]

    _fp_arg_regs = ["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"]

    def _get_argument(
        self, index: int, emulator: emulators.Emulator
    ) -> typing.Union[int, float]:
        if self.argument_types[index] in self._four_byte_types:
            return emulator.read_register(self._four_byte_arg_regs[index])

        elif self.argument_types[index] in self._eight_byte_types:
            return emulator.read_register(self._eight_byte_arg_regs[index])

        elif self.argument_types[index] == ArgumentType.FLOAT:
            intval = emulator.read_register(self._fp_arg_regs[index])
            intval &= self._int_mask
            byteval = intval.to_bytes(4, "little")
            (floatval,) = struct.unpack("<f", byteval)
            return floatval

        elif self.argument_types[index] == ArgumentType.DOUBLE:
            intval = emulator.read_register(self._fp_arg_regs[index])
            byteval = intval.to_bytes(8, "little")
            (floatval,) = struct.unpack("<d", byteval)
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
        emulator.write_register("rax", val)

    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a float"""
        data = struct.pack("<f", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("xmm0", intval)

    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a double"""
        data = struct.pack("<d", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("xmm0", intval)
