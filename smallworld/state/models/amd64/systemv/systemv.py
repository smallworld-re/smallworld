import struct

from ..... import emulators, platforms
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

    _soft_float = False
    _variadic_soft_float = False
    _floats_are_doubles = False
    _float_arg_regs = ["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"]
    _double_arg_regs = ["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"]

    _init_stack_offset = 8
    _align_stack = False
    _eight_byte_reg_size = 1
    _double_reg_size = 1
    _four_byte_stack_size = 8
    _eight_byte_stack_size = 8
    _float_stack_size = 8
    _double_stack_size = 8

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
