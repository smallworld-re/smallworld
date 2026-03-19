from ..... import emulators, platforms
from ...cstd import ArgumentType, CStdCallingContext, CStdModel
from ...posix.filedesc import POSIXFileDescriptorManager


class FileDescriptorManager(POSIXFileDescriptorManager):
    platform = platforms.Platform(platforms.Architecture.M68K, platforms.Byteorder.BIG)
    abi = platforms.ABI.SYSTEMV


class M68KSysVCallingContext(CStdCallingContext):
    platform = platforms.Platform(platforms.Architecture.M68K, platforms.Byteorder.BIG)
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

    def _return_pointer(self, emulator: emulators.Emulator, val: int) -> None:
        emulator.write_register("a0", val)

    def _read_return_pointer(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("a0")

    def _return_4_byte(self, emulator: emulators.Emulator, val: int) -> None:
        emulator.write_register("d0", val)

    def _read_return_4_byte(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register("d0")

    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        lo = val & self._int_inv_mask
        hi = (val >> 32) & self._int_inv_mask

        emulator.write_register("d0", hi)
        emulator.write_register("d1", lo)

    def _read_return_8_byte(self, emulator: emulators.Emulator) -> int:
        hi = emulator.read_register("d0")
        lo = emulator.read_register("d1")
        return lo + (hi << 32)

    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a float"""
        raise NotImplementedError("No idea how m68k floats work")

    def _read_return_float(self, emulator: emulators.Emulator) -> float:
        """Read a float returned value"""
        raise NotImplementedError("No idea how m68k floats work")

    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a double"""
        raise NotImplementedError("No idea how m68k floats work")

    def _read_return_double(self, emulator: emulators.Emulator) -> float:
        """Read a double returned value"""
        raise NotImplementedError("No idea how m68k floats work")


class M68KSysVModel(M68KSysVCallingContext, CStdModel):
    """Base class for C models using the m68k System V ABI"""

    pass
