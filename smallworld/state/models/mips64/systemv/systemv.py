import struct

from ..... import emulators, platforms
from ...cstd import ArgumentType, CStdCallingContext, CStdModel
from ...posix.filedesc import POSIXFileDescriptorManager


class FileDescriptorManager(POSIXFileDescriptorManager):
    platform = platforms.Platform(
        platforms.Architecture.MIPS64, platforms.Byteorder.BIG
    )
    abi = platforms.ABI.SYSTEMV


class MIPS64SysVCallingContext(CStdCallingContext):
    platform = platforms.Platform(
        platforms.Architecture.MIPS64, platforms.Byteorder.BIG
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

    _four_byte_arg_regs = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]

    _eight_byte_arg_regs = [
        "a0",
        "a1",
        "a2",
        "a3",
        "a4",
        "a5",
        "a6",
        "a7",
    ]

    _soft_float = False
    _variadic_soft_float = True
    _floats_are_doubles = False
    # n64 shares one argument-slot sequence between GP and FP registers: slot i
    # is a_i or f(12+i), so a leading integer shifts every following FP argument.
    _fp_shares_int_regs = True
    _float_arg_regs = [
        "f12",
        "f13",
        "f14",
        "f15",
        "f16",
        "f17",
        "f18",
        "f19",
    ]

    _double_arg_regs = [
        "f12",
        "f13",
        "f14",
        "f15",
        "f16",
        "f17",
        "f18",
        "f19",
    ]

    _init_stack_offset = 0
    _align_stack = True
    _eight_byte_reg_size = 1
    _double_reg_size = 1
    # The n64 ABI passes on-stack integer arguments in 8-byte slots, so a
    # 4-byte int consumes a full 8-byte slot; consecutive spilled ints must
    # advance by 8, not 4. Confirmed against mips64-linux-gnuabi64 output.
    _four_byte_stack_size = 8
    _eight_byte_stack_size = 8
    _float_stack_size = 4
    _double_stack_size = 8

    def _return_4_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return a four-byte type"""
        val &= self._int_inv_mask
        if val & self._int_sign_mask != 0:
            val |= self._int_signext_mask
        emulator.write_register("v0", val)

    def _read_return_4_byte(self, emulator: emulators.Emulator) -> int:
        """Read a four-byte returned value"""
        return emulator.read_register("v0") & self._int_inv_mask

    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return an eight-byte type"""
        emulator.write_register("v0", val)

    def _read_return_8_byte(self, emulator: emulators.Emulator) -> int:
        """Read an eight-byte returned value"""
        return emulator.read_register("v0")

    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a float"""
        data = struct.pack("<f", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("f0", intval)

    def _read_return_float(self, emulator: emulators.Emulator) -> float:
        """Read a float returned value"""
        # f0 is 64 bits wide; a single-precision return value sits in the
        # low 32 bits, so mask before packing or to_bytes overflows.
        intval = emulator.read_register("f0") & self._int_inv_mask
        data = int.to_bytes(intval, self._float_stack_size, "little")
        (unpacked,) = struct.unpack("<f", data)
        return unpacked

    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a double"""
        data = struct.pack("<d", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("f0", intval)

    def _read_return_double(self, emulator: emulators.Emulator) -> float:
        """Read a double returned value"""
        # n64 returns a double in the full 64-bit f0, so pack the double width
        # (8) -- _float_stack_size (4) truncated it and could not fill the <d
        # unpack.
        intval = emulator.read_register("f0")
        data = int.to_bytes(intval, self._double_stack_size, "little")
        (unpacked,) = struct.unpack("<d", data)
        return unpacked


class MIPS64SysVModel(MIPS64SysVCallingContext, CStdModel):
    """Base class for C models using the MIPS64 System V ABI"""

    pass
