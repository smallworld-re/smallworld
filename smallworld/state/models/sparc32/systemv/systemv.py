from ..... import emulators, platforms
from .....platforms.defs.sparc import SPARC_RETURN_ADDRESS_OFFSET
from ...cstd import ArgumentType, CStdCallingContext, CStdModel
from ...posix.filedesc import POSIXFileDescriptorManager
from ..model import SPARC32Model


class FileDescriptorManager(POSIXFileDescriptorManager):
    platform = platforms.Platform(
        platforms.Architecture.SPARC32, platforms.Byteorder.BIG
    )
    abi = platforms.ABI.SYSTEMV


class SPARC32SysVCallingContext(CStdCallingContext):
    """The 32-bit SPARC System V calling convention.

    Arguments are a sequence of words: the first six travel in %o0-%o5 and
    the rest on the stack, from %sp + 92 (past the 64-byte register-window
    save area, the hidden struct-return word, and home slots for the six
    register arguments). Eight-byte values take two consecutive words with no
    alignment, so one can be split between %o5 and the stack. Floating-point
    arguments travel the same way as integers.

    A model runs in its caller's register window -- it never executes `save`
    -- so it reads its arguments from the caller's %o registers and returns
    its result there, in %o0 (and %o1).
    """

    platform = platforms.Platform(
        platforms.Architecture.SPARC32, platforms.Byteorder.BIG
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

    _four_byte_arg_regs = [f"o{i}" for i in range(0, 6)]
    _eight_byte_arg_regs = [f"o{i}" for i in range(0, 6)]
    # SPARC passes arguments as one sequence of words: an eight-byte value
    # takes the next two, wherever they fall, and is split between the last
    # register and the stack when only one register is left.
    _align_eight_byte_regs = False
    _eight_byte_args_split = True

    _soft_float = True
    _variadic_soft_float = True
    _floats_are_doubles = False
    _float_arg_regs = []
    _double_arg_regs = []

    _init_stack_offset = 92
    _align_stack = False
    _eight_byte_reg_size = 2
    _double_reg_size = 2
    _four_byte_stack_size = 4
    _eight_byte_stack_size = 8
    _float_stack_size = 4
    _double_stack_size = 8

    def _return_4_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return a four-byte type"""
        emulator.write_register("o0", val)

    def _read_return_4_byte(self, emulator: emulators.Emulator) -> int:
        """Read a four-byte returned value"""
        return emulator.read_register("o0")

    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return an eight-byte type, high word in %o0"""
        emulator.write_register("o0", (val >> 32) & self._int_inv_mask)
        emulator.write_register("o1", val & self._int_inv_mask)

    def _read_return_8_byte(self, emulator: emulators.Emulator) -> int:
        """Read an eight-byte returned value"""
        hi = emulator.read_register("o0") & self._int_inv_mask
        lo = emulator.read_register("o1") & self._int_inv_mask
        return (hi << 32) | lo

    def set_return_address(
        self, emulator: emulators.Emulator, address: int, push=False
    ) -> None:
        """Return to `address` through %o7, which a return reads plus 8.

        This matches `SPARC32Model.get_return_address`.
        """
        emulator.write_register(
            "o7", (address - SPARC_RETURN_ADDRESS_OFFSET) & 0xFFFFFFFF
        )

    # SPARC returns floating-point values in %f0 (and %f1), and the SPARC32
    # platform does not model the floating-point registers.
    _NO_FP_RETURN = (
        "SPARC returns floating-point values in %f0, "
        "which the SPARC32 platform does not model"
    )

    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a float"""
        raise NotImplementedError(self._NO_FP_RETURN)

    def _read_return_float(self, emulator: emulators.Emulator) -> float:
        """Read a float returned value"""
        raise NotImplementedError(self._NO_FP_RETURN)

    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a double"""
        raise NotImplementedError(self._NO_FP_RETURN)

    def _read_return_double(self, emulator: emulators.Emulator) -> float:
        """Read a double returned value"""
        raise NotImplementedError(self._NO_FP_RETURN)


class SPARC32SysVModel(SPARC32SysVCallingContext, SPARC32Model, CStdModel):
    """Base class for C models using the 32-bit SPARC System V ABI"""

    pass
