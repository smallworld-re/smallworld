import struct
import typing

from ..... import emulators, platforms
from ...cstd import ArgumentType, CStdCallingContext, CStdModel
from ...posix.filedesc import POSIXFileDescriptorManager


class FileDescriptorManager(POSIXFileDescriptorManager):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V7A, platforms.Byteorder.LITTLE
    )
    abi = platforms.ABI.SYSTEMV


class ArmHFSysVCallingContext(CStdCallingContext):
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
    # AAPCS-VFP passes FP arguments in s0-s15 (16 single-precision) and d0-d7
    # (8 double-precision), whose banks physically alias (d(k) == s(2k):s(2k+1)).
    # _next_fp_register below allocates them with the AAPCS back-fill rule.
    _float_arg_regs = [f"s{i}" for i in range(16)]
    _double_arg_regs = [f"d{i}" for i in range(8)]

    _init_stack_offset = 0
    _align_stack = True
    _eight_byte_reg_size = 2
    _double_reg_size = 1
    _four_byte_stack_size = 4
    _eight_byte_stack_size = 8
    _float_stack_size = 4
    _double_stack_size = 8

    def _next_fp_register(self, kind: ArgumentType) -> typing.Optional[int]:
        """Allocate an FP argument register per the AAPCS-VFP back-fill rule.

        Single-precision arguments take the lowest free s register (back-filling
        holes an aligned double left behind); double-precision arguments take
        the lowest free even s-pair, i.e. a d register (d(k) == s(2k):s(2k+1)).
        Once any FP argument is passed on the stack, every not-yet-allocated VFP
        register is marked unavailable, so a later single-precision argument
        cannot back-fill past a stacked argument.
        """
        # Set of allocated single-precision (s) register indices. Created lazily
        # because models initialize the calling context through
        # CStdCallingContext.__init__ directly, bypassing __init__ here.
        if not hasattr(self, "_vfp_used"):
            self._vfp_used: typing.Set[int] = set()
        used = self._vfp_used
        n = len(self._float_arg_regs)  # 16 single-precision registers

        if kind == ArgumentType.FLOAT:
            for s in range(n):
                if s not in used:
                    used.add(s)
                    return s
        else:  # ArgumentType.DOUBLE
            for d in range(len(self._double_arg_regs)):
                lo, hi = 2 * d, 2 * d + 1
                if lo not in used and hi not in used:
                    used.add(lo)
                    used.add(hi)
                    return d

        # Exhausted: mark all remaining VFP registers unavailable.
        used.update(range(n))
        return None

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

    def _read_return_float(self, emulator: emulators.Emulator) -> float:
        """Read a float returned value"""
        intval = emulator.read_register("s0")
        data = int.to_bytes(intval, self._float_stack_size, "little")
        (unpacked,) = struct.unpack("<f", data)
        return unpacked

    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a double"""
        data = struct.pack("<d", val)
        intval = int.from_bytes(data, "little")
        emulator.write_register("d0", intval)

    def _read_return_double(self, emulator: emulators.Emulator) -> float:
        """Read a double returned value"""
        as_int = emulator.read_register("d0")
        as_bytes = int.to_bytes(as_int, 8, "little")
        (unpacked,) = struct.unpack("<d", as_bytes)
        return unpacked


class ArmHFSysVModel(ArmHFSysVCallingContext, CStdModel):
    """Base class for C models using the ARM32 GNU EABI

    This is a specific ARM System V ABI.
    It generally applies to ARMv7.
    """

    pass
