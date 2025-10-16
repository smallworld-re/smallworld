import struct

from ..... import emulators, platforms
from ...cstd import ArgumentType, CStdCallingContext, CStdModel


class MIPSELSysVCallingContext(CStdCallingContext):
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
        """Return a four-byte type"""
        emulator.write_register("v0", val)

    def _read_return_4_byte(self, emulator: emulators.Emulator) -> int:
        """Read a four-byte returned value"""
        return emulator.read_register("v0")

    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return an eight-byte type"""
        lo = val & self._int_inv_mask
        hi = (val >> 32) & self._int_inv_mask

        emulator.write_register("v0", lo)
        emulator.write_register("v1", hi)

    def _read_return_8_byte(self, emulator: emulators.Emulator) -> int:
        """Read an eight-byte returned value"""
        lo = emulator.read_register("v0")
        hi = emulator.read_register("v1")

        return lo + (hi << 32)

    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a float"""
        data = struct.pack("<f", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("f0", intval)

    def _read_return_float(self, emulator: emulators.Emulator) -> float:
        """Read a float returned value"""
        intval = emulator.read_register("f0")
        data = int.to_bytes(intval, self._float_stack_size, "little")
        (unpacked,) = struct.unpack("<f", data)
        return unpacked

    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a double"""
        data = struct.pack("<d", val)
        intval = int.from_bytes(data, "little")

        lo = intval & self._int_inv_mask
        hi = (intval >> 32) & self._int_inv_mask

        emulator.write_register("f0", lo)
        emulator.write_register("f1", hi)

    def _read_return_double(self, emulator: emulators.Emulator) -> float:
        """Read a double returned value"""
        lo = emulator.read_register("f0")
        hi = emulator.read_register("f1")
        as_int = lo + (hi << 32)
        as_bytes = int.to_bytes(as_int, 8, "little")
        (unpacked,) = struct.unpack("<d", as_bytes)
        return unpacked


class MIPSELSysVModel(MIPSELSysVCallingContext, CStdModel):
    """Base class for C models using the MIPS o32 ABI"""

    pass
