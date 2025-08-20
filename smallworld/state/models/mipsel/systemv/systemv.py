import struct

from ..... import emulators, platforms
from ...cstd import ArgumentType, CStdModel


class MIPSELSysVModel(CStdModel):
    """Base class for C models using the MIPS o32 ABI"""

    platform = platforms.Platform(
        platforms.Architecture.MIPS32, platforms.Byteorder.LITTLE
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

    _four_byte_arg_regs = ["a0", "a1", "a2", "a3"]
    _eight_byte_arg_regs = ["a0", "a1", "a2", "a3"]

    _soft_float = True
    _variadic_soft_float = True
    _floats_are_doubles = False
    _float_arg_regs = []
    _double_arg_regs = []

    _init_stack_offset = 16
    _align_stack = True
    _eight_byte_reg_size = 2
    _double_reg_size = 2
    _four_byte_stack_size = 4
    _eight_byte_stack_size = 8
    _float_stack_size = 4
    _double_stack_size = 8

    def _return_4_byte(self, emulator: emulators.Emulator, val: int) -> None:
        emulator.write_register("v0", val)

    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        lo = val & self._int_inv_mask
        hi = (val >> 32) & self._int_inv_mask

        emulator.write_register("v0", lo)
        emulator.write_register("v1", hi)

    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        data = struct.pack("<f", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("f0", intval)

    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        data = struct.pack("<d", val)
        intval = int.from_bytes(data, "little")

        lo = intval & self._int_inv_mask
        hi = (intval >> 32) & self._int_inv_mask

        emulator.write_register("f0", lo)
        emulator.write_register("f1", hi)
