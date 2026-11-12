import struct
import typing

from ..... import emulators, platforms
from ...cstd import ArgumentType, CStdCallingContext, CStdModel
from ...posix.filedesc import POSIXFileDescriptorManager


class FileDescriptorManager(POSIXFileDescriptorManager):
    platform = platforms.Platform(
        platforms.Architecture.POWERPC64, platforms.Byteorder.BIG
    )
    abi = platforms.ABI.SYSTEMV


class PowerPC64SysVCallingContext(CStdCallingContext):
    """The 64-bit PowerPC ELFv2 calling convention

    Every argument occupies a doubleword "slot" of the parameter save area.
    The first eight slots are passed in r3-r10; the rest are on the stack.
    Floating-point arguments are passed in f1-f13, in order,
    but each one still uses up the general-purpose register (or stack slot)
    its slot maps to.

    A single-precision argument that doesn't fit in f1-f13 is stored in
    its stack slot as a single-precision value, in the slot's second word
    (GCC's and clang's callers `stfs` the 14th argument to sp+140, and
    their callees `lfs` it from there).  An int is extended to its whole
    doubleword by signedness, in a register or on the stack.

    NOTE: Only ELFv2 is modeled.  ELFv1 differs mainly in its use of
    function descriptors, which models don't see; the argument registers
    are the same, but its parameter save area starts 16 bytes higher.
    """

    platform = platforms.Platform(
        platforms.Architecture.POWERPC64, platforms.Byteorder.BIG
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

    _four_byte_arg_regs = ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"]

    _eight_byte_arg_regs = ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"]

    _soft_float = False
    # Variadic floating-point arguments are read from the general-purpose
    # registers (and stack), where the caller also places them.
    _variadic_soft_float = True
    # The FPRs always hold double-precision values,
    # including single-precision arguments and return values.
    _floats_are_doubles = True
    _float_arg_regs = [f"f{i}" for i in range(1, 14)]
    _double_arg_regs = [f"f{i}" for i in range(1, 14)]

    # The parameter save area starts after the 32-byte frame header,
    # and its first eight doublewords back r3-r10.
    _init_stack_offset = 32 + 8 * 8
    _align_stack = False
    _eight_byte_reg_size = 1
    _double_reg_size = 1
    _four_byte_stack_size = 8
    _eight_byte_stack_size = 8
    _float_stack_size = 4
    _double_stack_size = 8

    def _next_fp_register(self, kind: ArgumentType) -> typing.Optional[int]:
        """Allocate the next FPR, and use up the slot it maps to.

        The base allocator gives FP arguments their own register sequence,
        which is right for the FPRs here, but leaves the argument's slot free
        for the next integer argument; ELFv2 doesn't.
        """
        fp_offset = super()._next_fp_register(kind)
        if fp_offset is not None:
            if self._int_reg_offset < len(self._eight_byte_arg_regs):
                self._int_reg_offset += 1
            else:
                self._stack_offset += self._double_stack_size
        return fp_offset

    def set_argument(
        self,
        index: int,
        emulator: emulators.Emulator,
        value: typing.Union[int, float],
    ):
        if (
            self.argument_types[index] == ArgumentType.FLOAT
            and self._on_stack[index]
            and isinstance(value, float)
        ):
            emulator.write_memory(
                self._single_stack_address(index, emulator), struct.pack(">f", value)
            )
            return
        super().set_argument(index, emulator, value)
        if self.argument_types[index] == ArgumentType.INT and isinstance(value, int):
            # The caller extends an int to its whole doubleword slot by
            # signedness, and compiled callees rely on it (a `long f(int x)`
            # returns r3 unchanged).  The base class writes only the low
            # word; unsigned ints come out right that way, signed ones don't.
            val = value & self._int_inv_mask
            if val & self._int_sign_mask:
                val |= self._int_signext_mask
            if self._on_stack[index]:
                addr = (
                    emulator.read_register(self.platdef.sp_register)
                    + self._arg_offset[index]
                )
                emulator.write_memory(addr, val.to_bytes(8, "big"))
            else:
                emulator.write_register(
                    self._four_byte_arg_regs[self._arg_offset[index]], val
                )

    def get_argument(
        self,
        index: int,
        kind: ArgumentType,
        emulator: emulators.Emulator,
    ) -> typing.Union[int, float]:
        if kind == ArgumentType.FLOAT and self._on_stack[index]:
            data = emulator.read_memory(self._single_stack_address(index, emulator), 4)
            (value,) = struct.unpack(">f", data)
            return value
        return super().get_argument(index, kind, emulator)

    def _single_stack_address(self, index: int, emulator: emulators.Emulator) -> int:
        """Where a single-precision argument sits in its stack slot."""
        return (
            emulator.read_register(self.platdef.sp_register)
            + self._arg_offset[index]
            + 4
        )

    def begin_call(
        self,
        emulator: emulators.Emulator,
        address: int,
        args: typing.Sequence[typing.Union[int, float]],
        return_address: int,
    ) -> None:
        # A function's global entry point derives the TOC pointer, r2,
        # from its own address in r12.
        emulator.write_register("r12", address)
        super().begin_call(emulator, address, args, return_address)

    def _return_4_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return a four-byte type"""
        # The ABI extends a four-byte return value to fill r3
        # according to its signedness.
        val &= self._int_inv_mask
        if self.return_type == ArgumentType.INT and val & self._int_sign_mask:
            val |= self._int_signext_mask
        emulator.write_register("r3", val)

    def _read_return_4_byte(self, emulator: emulators.Emulator) -> int:
        """Read a four-byte returned value"""
        return emulator.read_register("r3") & self._int_inv_mask

    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return an eight-byte type"""
        emulator.write_register("r3", val)

    def _read_return_8_byte(self, emulator: emulators.Emulator) -> int:
        """Read an eight-byte returned value"""
        return emulator.read_register("r3")

    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a float"""
        # NOTE: f1 holds a single-precision result in double format
        (val,) = struct.unpack(">f", struct.pack(">f", val))
        self._return_double(emulator, val)

    def _read_return_float(self, emulator: emulators.Emulator) -> float:
        """Read a float returned value"""
        # NOTE: f1 holds a single-precision result in double format
        return self._read_return_double(emulator)

    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a double"""
        data = struct.pack(">d", val)
        intval = int.from_bytes(data, "big")
        emulator.write_register("f1", intval)

    def _read_return_double(self, emulator: emulators.Emulator) -> float:
        """Read a double returned value"""
        intval = emulator.read_register("f1")
        data = int.to_bytes(intval, self._double_stack_size, "big")
        (unpacked,) = struct.unpack(">d", data)
        return unpacked


class PowerPC64SysVModel(PowerPC64SysVCallingContext, CStdModel):
    """Base class for C models using the 64-bit PowerPC ELFv2 System V ABI"""

    pass
