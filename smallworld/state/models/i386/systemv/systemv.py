from ..... import emulators, platforms
from ...cstd import ArgumentType, CStdModel


class I386SysVModel(CStdModel):
    """Base class for C models using the I386 System V ABI"""

    platform = platforms.Platform(
        platforms.Architecture.X86_32, platforms.Byteorder.LITTLE
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

    _four_byte_arg_regs = []
    _eight_byte_arg_regs = []

    _soft_float = False
    _variadic_soft_float = False
    _floats_are_doubles = False
    _float_arg_regs = []
    _double_arg_regs = []

    _init_stack_offset = 4
    _align_stack = False
    _eight_byte_reg_size = 1
    _double_reg_size = 1
    _four_byte_stack_size = 4
    _eight_byte_stack_size = 8
    _float_stack_size = 4
    _double_stack_size = 8

    def _return_4_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return a four-byte type"""
        emulator.write_register("eax", val)

    def _read_return_4_byte(self, emulator: emulators.Emulator) -> int:
        """Read a four-byte returned value"""
        return emulator.read_register("eax")

    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return an eight-byte type"""
        hi = (val >> 32) & self._int_inv_mask
        lo = val & self._int_inv_mask

        emulator.write_register("eax", lo)
        emulator.write_register("edx", hi)

    def _read_return_8_byte(self, emulator: emulators.Emulator) -> int:
        """Read an eight-byte returned value"""
        lo = emulator.read_register("eax")
        hi = emulator.read_register("edx")

        return lo + (hi << 32)

    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a float"""
        raise NotImplementedError("i386 System-V uses x87 registers to return floats")

    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a double"""
        raise NotImplementedError("i386 System-V uses x87 registers to return doubles")
