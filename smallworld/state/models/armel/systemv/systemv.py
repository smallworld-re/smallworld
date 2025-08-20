import struct

from ..... import emulators, platforms
from ...cstd import ArgumentType, CStdModel


class ArmELSysVModel(CStdModel):
    """Base class for C models using the ARM32 GNU EABI

    This is a specific ARM System V ABI.
    It generally applies to ARMv5t or ARMv6.
    """

    platform = platforms.Platform(
        platforms.Architecture.ARM_V5T, platforms.Byteorder.LITTLE
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

    _four_byte_arg_regs = ["r0", "r1", "r2", "r3"]
    _eight_byte_arg_regs = ["r0", "r1", "r2", "r3"]

    _soft_float = True
    _variadic_soft_float = True
    _floats_are_doubles = False
    _float_arg_regs = []
    _double_arg_regs = []

    _init_stack_offset = 0
    _align_stack = True
    _eight_byte_reg_size = 2
    _double_reg_size = 2
    _four_byte_stack_size = 4
    _eight_byte_stack_size = 8
    _float_stack_size = 4
    _double_stack_size = 8

    def _return_4_byte(self, emulator: emulators.Emulator, val: int) -> None:
        emulator.write_register("r0", val)

    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        lo = val & self._int_inv_mask
        hi = val >> 32 & self._int_inv_mask

        emulator.write_register("r0", lo)
        emulator.write_register("r1", hi)

    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        data = struct.pack("<f", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("r0", intval)

    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        data = struct.pack("<d", val)
        intval = int.from_bytes(data, "little")

        lo = intval & self._int_inv_mask
        hi = (intval >> 32) & self._int_inv_mask

        emulator.write_register("r0", lo)
        emulator.write_register("r1", hi)
