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

    def __init__(self, address: int):
        super().__init__(address)

        self._int_args = dict()
        self._fp_args = dict()

        int_arg_idx = 0
        fp_arg_idx = 0

        for idx in range(0, len(self.argument_types)):
            arg = self.argument_types[idx]
            if arg in self._four_byte_types or arg in self._eight_byte_types:
                self._int_args[idx] = int_arg_idx
                int_arg_idx += 1
            elif arg in (ArgumentType.FLOAT, ArgumentType.DOUBLE):
                self._fp_args[idx] = fp_arg_idx
                fp_arg_idx += 1
            else:
                raise Exception(
                    f"Unknown argument type {arg} for argument {idx} of {self.name}"
                )

    def _get_argument(
        self,
        index: int,
        kind: ArgumentType,
        emulator: emulators.Emulator,
        absolute: bool = False,
    ) -> typing.Union[int, float]:
        if kind in self._four_byte_types:
            index = self._int_args[index]
            return emulator.read_register(self._four_byte_arg_regs[index])

        elif kind in self._eight_byte_types:
            index = self._int_args[index]
            return emulator.read_register(self._eight_byte_arg_regs[index])

        elif kind == ArgumentType.FLOAT:
            index = self._fp_args[index]
            intval = emulator.read_register(self._fp_arg_regs[index])
            intval &= self._int_inv_mask
            byteval = intval.to_bytes(4, "little")
            (floatval,) = struct.unpack("<f", byteval)
            return floatval

        elif kind == ArgumentType.DOUBLE:
            index = self._fp_args[index]
            intval = emulator.read_register(self._fp_arg_regs[index])
            byteval = intval.to_bytes(8, "little")
            (floatval,) = struct.unpack("<d", byteval)
            return floatval

        else:
            raise exceptions.ConfigurationError(
                "Unknown type {kind} for argument {i + 1} of {self.name}"
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
