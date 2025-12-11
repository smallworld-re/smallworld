import struct

from ..... import emulators, platforms
from ...cstd import ArgumentType, CStdCallingContext, CStdModel


class PowerPCSysVCallingContext(CStdCallingContext):
    platform = platforms.Platform(
        platforms.Architecture.POWERPC32, platforms.Byteorder.BIG
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

    _four_byte_arg_regs = [
        "r3",
        "r4",
        "r5",
        "r6",
        "r7",
        "r8",
        "r9",
        "r10",
    ]

    _eight_byte_arg_regs = [
        "r3",
        "r4",
        "r5",
        "r6",
        "r7",
        "r8",
        "r9",
        "r10",
    ]

    _soft_float = False
    _variadic_soft_float = False
    _floats_are_doubles = True
    _float_arg_regs = ["f1", "f2", "f3", "f4", "f5", "f6"]
    _double_arg_regs = ["f1", "f2", "f3", "f4", "f5", "f6"]

    _init_stack_offset = 8
    _align_stack = True
    _eight_byte_reg_size = 2
    _double_reg_size = 1
    _four_byte_stack_size = 4
    _eight_byte_stack_size = 8
    _float_stack_size = 4
    _double_stack_size = 8

    def _return_4_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return a four-byte type"""
        emulator.write_register("r3", val & self._int_inv_mask)

    def _read_return_4_byte(self, emulator: emulators.Emulator) -> int:
        """Read a four-byte returned value"""
        return emulator.read_register("r3")

    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return an eight-byte type"""
        lo = val & self._int_inv_mask
        hi = val >> 32 & self._int_inv_mask

        emulator.write_register("r3", hi)
        emulator.write_register("r4", lo)

    def _read_return_8_byte(self, emulator: emulators.Emulator) -> int:
        """Read an eight-byte returned value"""
        hi = emulator.read_register("r3")
        lo = emulator.read_register("r4")

        return lo + (hi << 32)

    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a float"""
        # NOTE: powerpc promotes floats to doubles
        data = struct.pack("<d", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("f1", intval)

    def _read_return_float(self, emulator: emulators.Emulator) -> float:
        """Read a float returned value"""
        # NOTE: powerpc promotes floats to doubles
        intval = emulator.read_register("f1")
        data = int.to_bytes(intval, self._double_stack_size, "little")
        (unpacked,) = struct.unpack("<d", data)
        return unpacked

    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a double"""
        data = struct.pack("<d", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("f1", intval)

    def _read_return_double(self, emulator: emulators.Emulator) -> float:
        """Read a double returned value"""
        intval = emulator.read_register("f1")
        data = int.to_bytes(intval, self._double_stack_size, "little")
        (unpacked,) = struct.unpack("<d", data)
        return unpacked


class PowerPCSysVModel(PowerPCSysVCallingContext, CStdModel):
    """Base class for C models using the PowerPC System-V ABI"""

    pass
