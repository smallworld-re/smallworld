import struct

from ..... import emulators, platforms
from ...cstd import ArgumentType, CStdModel


class ArmHFSysVModel(CStdModel):
    """Base class for C models using the ARM32 GNU EABI

    This is a specific ARM System V ABI.
    It generally applies to ARMv7.
    """

    platform = platforms.Platform(
        platforms.Architecture.ARM_V7A, platforms.Byteorder.LITTLE
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

    _soft_float = False
    _variadic_soft_float = True
    _floats_are_doubles = False
    _float_arg_regs = ["s0", "s1", "s2", "s3", "s4", "s5", "s6"]
    _double_arg_regs = ["d0", "d1", "d2", "d3", "d4", "d5", "d6"]

    _init_stack_offset = 0
    _align_stack = True
    _eight_byte_reg_size = 2
    _double_reg_size = 1
    _four_byte_stack_size = 4
    _eight_byte_stack_size = 8
    _float_stack_size = 4
    _double_stack_size = 8

    def _return_4_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return a four-byte type"""
        emulator.write_register("r0", val)

    def _read_return_4_byte(self, emulator: emulators.Emulator) -> int:
        """Read a four-byte returned value"""
        return emulator.read_register("r0")

    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return an eight-byte type"""
        lo = val & self._int_inv_mask
        hi = val >> 32 & self._int_inv_mask

        emulator.write_register("r0", lo)
        emulator.write_register("r1", hi)

    def _read_return_8_byte(self, emulator: emulators.Emulator) -> int:
        """Read an eight-byte returned value"""
        lo = emulator.read_register("r0")
        hi = emulator.read_register("r1")

        return lo + (hi << 32)

    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a float"""
        data = struct.pack("<f", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("s0", intval)

    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a double"""
        data = struct.pack("<d", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("d0", intval)
