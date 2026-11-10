import struct

from ..... import emulators, platforms
from ...cstd import ArgumentType, CStdCallingContext, CStdModel
from ...posix.filedesc import POSIXFileDescriptorManager


class FileDescriptorManager(POSIXFileDescriptorManager):
    platform = platforms.Platform(
        platforms.Architecture.RISCV32, platforms.Byteorder.LITTLE
    )
    abi = platforms.ABI.SYSTEMV


class RiscV32SysVCallingContext(CStdCallingContext):
    """The RiscV ilp32d calling convention"""

    platform = platforms.Platform(
        platforms.Architecture.RISCV32, platforms.Byteorder.LITTLE
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

    _four_byte_arg_regs = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]

    _eight_byte_arg_regs = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]

    _soft_float = False
    # Variadic floating-point arguments go in integer register pairs.
    _variadic_soft_float = True
    _floats_are_doubles = False
    _float_arg_regs = ["fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7"]

    _double_arg_regs = ["fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7"]

    _init_stack_offset = 0
    # 8-byte values on the stack are 8-byte aligned.
    _align_stack = True
    _eight_byte_reg_size = 2
    # A fixed 8-byte argument takes the next two argument registers,
    # but a variadic one starts on an even-numbered register.  With only a7
    # left, a fixed one is split between a7 and the stack.
    _align_eight_byte_regs = False
    _variadic_align_eight_byte_regs = True
    _split_eight_byte_args = True
    # A floating-point argument with no FP register left goes in integer
    # registers while any are free.
    _fp_falls_back_to_int_regs = True
    _double_reg_size = 1
    _four_byte_stack_size = 4
    _eight_byte_stack_size = 8
    _float_stack_size = 4
    _double_stack_size = 8

    def _return_4_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return a four-byte type"""
        emulator.write_register("a0", val & self._int_inv_mask)

    def _read_return_4_byte(self, emulator: emulators.Emulator) -> int:
        """Read a four-byte returned value"""
        return emulator.read_register("a0")

    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return an eight-byte type"""
        lo = val & self._int_inv_mask
        hi = val >> 32 & self._int_inv_mask
        emulator.write_register("a0", lo)
        emulator.write_register("a1", hi)

    def _read_return_8_byte(self, emulator: emulators.Emulator) -> int:
        """Read an eight-byte returned value"""
        lo = emulator.read_register("a0")
        hi = emulator.read_register("a1")
        return lo + (hi << 32)

    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a float"""
        data = struct.pack("<f", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("fa0", intval)

    def _read_return_float(self, emulator: emulators.Emulator) -> float:
        """Read a float returned value"""
        intval = emulator.read_register("fa0") & self._int_inv_mask
        data = int.to_bytes(intval, self._float_stack_size, "little")
        (unpacked,) = struct.unpack("<f", data)
        return unpacked

    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a double"""
        data = struct.pack("<d", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("fa0", intval)

    def _read_return_double(self, emulator: emulators.Emulator) -> float:
        """Read a double returned value"""
        intval = emulator.read_register("fa0")
        data = int.to_bytes(intval, self._double_stack_size, "little")
        (unpacked,) = struct.unpack("<d", data)
        return unpacked


class RiscV32SysVModel(RiscV32SysVCallingContext, CStdModel):
    """Base class for C models using the RiscV32 System V ABI"""

    pass
