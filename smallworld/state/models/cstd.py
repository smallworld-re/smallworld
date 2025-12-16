import abc
import enum
import logging
import struct
import typing

from smallworld import platforms, utils
from smallworld.exceptions.exceptions import ConfigurationError

from ... import emulators, exceptions
from ...platforms import Byteorder, PlatformDef
from .model import Model

log = logging.getLogger(__name__)


class ArgumentType(enum.Enum):
    """C primitive data types for specifying function arguments.

    The exact size of these types depends strongly on the ABI.
    These specify the source-level signature;
    the ABI-specific subclasses of CStdModel figure out how to decode them.
    """

    CHAR = "char"
    UCHAR = "unsigned char"

    SHORT = "short"
    USHORT = "unsigned short"

    INT = "int"
    UINT = "unsigned int"

    LONG = "long"
    ULONG = "unsigned long"

    POINTER = "pointer"

    SIZE_T = "size_t"
    SSIZE_T = "ssize_t"

    LONGLONG = "long long"
    ULONGLONG = "unsigned long long"

    FLOAT = "float"
    DOUBLE = "double"

    VOID = "void"


signed_int_types = {
    ArgumentType.INT,
    ArgumentType.LONG,
    ArgumentType.LONGLONG,
    ArgumentType.SSIZE_T,
}


class CStdCallingContext(metaclass=abc.ABCMeta):
    argument_types: typing.List[ArgumentType] = []
    return_type: ArgumentType = ArgumentType.VOID

    def __init__(self):
        self.platdef: PlatformDef = PlatformDef.for_platform(self.platform)

        self._int_reg_offset = 0
        self._fp_reg_offset = 0
        self._stack_offset = 0

        self._on_stack: typing.List[bool] = list()
        self._arg_offset: typing.List[int] = list()

        self.set_argument_types(self.argument_types)

    @property
    @abc.abstractmethod
    def platform(self) -> platforms.Platform:
        """The platform for which this model is defined."""
        pass

    @property
    @abc.abstractmethod
    def abi(self) -> platforms.ABI:
        """The ABI for which this model is defined."""
        pass

    @classmethod
    def for_platform(cls, platform: platforms.Platform):
        """Find the appropriate CStdCallingContext for your architecture

        Arguments:
            platform: The platform you want

        Returns:
            An instance of the appropriate CStdCallingContext

        Raises:
            ValueError: If no CStdCallingContext subclass matches your request
        """
        try:
            return utils.find_subclass(cls, lambda x: x.platform == platform)
        except:
            raise ValueError(
                f"No CStdCallingContext for {platform.architecture}:{platform.byteorder}"
            )

    # *** Integer arithmetic constants ***
    #
    # Generalized bitmasks for specific types,
    # determined by their size on this ABI.

    _char_sign_mask: int = 0x80
    _char_inv_mask: int = 0xFF

    _short_sign_mask: int = 0x8000
    _short_inv_mask: int = 0xFFFF

    @property
    @abc.abstractmethod
    def _int_sign_mask(self) -> int:
        # Bitmask covering the sign bit of an int
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _int_inv_mask(self) -> int:
        # Bitmask covering all bits of an int
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _long_sign_mask(self) -> int:
        # Bitmask covering the sign bit of a long
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _long_long_inv_mask(self) -> int:
        # Bitmask covering all bits of a lon
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _long_long_sign_mask(self) -> int:
        # Bitmask covering the sign bit of a long long
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _long_inv_mask(self) -> int:
        # Bitmask covering all bits of a long long
        raise NotImplementedError()

    # Mask for sign-extending 32-bit numbers to 64-bit.
    _int_signext_mask = 0xFFFFFFFF00000000

    # *** Configuration Constants ***
    #
    # It turns out most ABIs follow a generalizable pattern
    # when it comes to passing arguments.
    #
    # The following static fields are the configurations for this pattern.
    # The actual implementation for adding an argument to the signature,
    # and fetching an argument from the emulator
    # are in the functions `add_argument` and `get_argument`.
    #
    # These are separate because they're used by fixed and variadic calls,
    # which are handled separately.

    @property
    @abc.abstractmethod
    def _four_byte_types(self) -> typing.Set[ArgumentType]:
        """Types that are four bytes in this ABI."""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _eight_byte_types(self) -> typing.Set[ArgumentType]:
        """Types that are eight bytes in this ABI."""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _four_byte_arg_regs(self) -> typing.List[str]:
        """Registers for four-byte arguments"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _eight_byte_arg_regs(self) -> typing.List[str]:
        """Registers for eight-byte arguments"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _soft_float(self) -> bool:
        """Use int regs for fp arguments"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _variadic_soft_float(self) -> bool:
        """Use int regs for fp arguments for variadic args"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _floats_are_doubles(self) -> bool:
        """Floats are actually stored as doubles"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _float_arg_regs(self) -> typing.List[str]:
        """Registers for float arguments"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _double_arg_regs(self) -> typing.List[str]:
        """Registers for double arguments"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _init_stack_offset(self) -> int:
        """Initial offset for stack arguments"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _align_stack(self) -> bool:
        """Align stack for eight-byte values"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _eight_byte_reg_size(self) -> int:
        """Number of registers required for an eight-byte value"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _double_reg_size(self) -> int:
        """Number of registers required for a double value"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _four_byte_stack_size(self) -> int:
        """Size of a four-byte argument on the stack.  Not always four bytes"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _eight_byte_stack_size(self) -> int:
        """Size of an eight-byte argument on the stack."""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _float_stack_size(self) -> int:
        """Size of a float on the stack"""
        raise NotImplementedError()

    @property
    def _double_stack_size(self) -> int:
        """Size of a double on the stack"""
        raise NotImplementedError()

    @abc.abstractmethod
    def _return_4_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return a four-byte type"""
        raise NotImplementedError()

    @abc.abstractmethod
    def _read_return_4_byte(self, emulator: emulators.Emulator) -> int:
        """Read a four-byte returned value"""
        raise NotImplementedError()

    @abc.abstractmethod
    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return an eight-byte type"""
        raise NotImplementedError()

    @abc.abstractmethod
    def _read_return_8_byte(self, emulator: emulators.Emulator) -> int:
        """Read an eight-byte returned value"""
        raise NotImplementedError()

    @abc.abstractmethod
    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a float"""
        raise NotImplementedError()

    @abc.abstractmethod
    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a double"""
        raise NotImplementedError()

    @abc.abstractmethod
    def _read_return_float(self, emulator: emulators.Emulator) -> float:
        """Return a float"""
        raise NotImplementedError()

    @abc.abstractmethod
    def _read_return_double(self, emulator: emulators.Emulator) -> float:
        """Return a double"""
        raise NotImplementedError()

    def add_argument(
        self: typing.Union["CStdCallingContext", "VariadicContext"],
        i: int,
        kind: ArgumentType,
    ):
        if kind in self._four_byte_types or (
            kind == ArgumentType.FLOAT and self._soft_float
        ):
            # Four byte int type, or float on a system without separate FP arg regs
            if self._int_reg_offset == len(self._four_byte_arg_regs):
                # No room left in registers; use stack
                self._on_stack.append(True)
                self._arg_offset.append(self._stack_offset + self._init_stack_offset)
                self._stack_offset += self._four_byte_stack_size
            else:
                # Registers left; use them
                self._on_stack.append(False)
                self._arg_offset.append(self._int_reg_offset)
                self._int_reg_offset += 1
        elif kind in self._eight_byte_types or (
            kind == ArgumentType.DOUBLE and self._soft_float
        ):
            # Eight byte int type, or double on a system without separate FP arg regs
            if self._int_reg_offset % self._eight_byte_reg_size != 0:
                # Align argument register for eight-byte value
                self._int_reg_offset += 1

            if self._int_reg_offset == len(self._eight_byte_arg_regs):
                # No room left in registers; use stack
                if (
                    self._align_stack
                    and self._stack_offset % self._eight_byte_stack_size != 0
                ):
                    # Stack out of alignment.  Align it.
                    self._stack_offset += 4
                self._on_stack.append(True)
                self._arg_offset.append(self._stack_offset + self._init_stack_offset)
                self._stack_offset += self._eight_byte_stack_size
            else:
                # Registers left; use them
                self._on_stack.append(False)
                self._arg_offset.append(self._int_reg_offset)
                self._int_reg_offset += self._eight_byte_reg_size
        elif kind == ArgumentType.FLOAT:
            # Float type
            if self._fp_reg_offset == len(self._float_arg_regs):
                # No room left in registers; use stack
                self._on_stack.append(True)
                self._arg_offset.append(self._stack_offset + self._init_stack_offset)
                self._stack_offset += self._float_stack_size
            else:
                # Registers left; use them
                self._on_stack.append(False)
                self._arg_offset.append(self._fp_reg_offset)
                self._fp_reg_offset += 1
        elif kind == ArgumentType.DOUBLE:
            # Double type
            if self._fp_reg_offset % self._double_reg_size != 0:
                self._fp_reg_offset += 1

            if self._fp_reg_offset == len(self._double_arg_regs):
                # No room left in registers; use stack
                if (
                    self._align_stack
                    and self._stack_offset % self._double_stack_size != 0
                ):
                    self._stack_offset += 4
                self._on_stack.append(True)
                self._arg_offset.append(self._stack_offset + self._init_stack_offset)
                self._stack_offset += self._double_stack_size
            else:
                # Registers left; use them
                self._on_stack.append(False)
                self._arg_offset.append(self._fp_reg_offset)
                self._fp_reg_offset += self._double_reg_size
        else:
            raise exceptions.ConfigurationError(f"Argument {i} has unknown type {kind}")

    def set_argument_types(self, argument_types: list[ArgumentType]) -> None:
        self.argument_types = argument_types
        for i, t in enumerate(argument_types):
            self.add_argument(i, t)

    def set_argument(
        self,
        index: int,
        emulator: emulators.Emulator,
        value: int | float,
    ):
        # There are some cases where passing floats is not supported
        if self.argument_types[index] in [ArgumentType.FLOAT, ArgumentType.DOUBLE]:
            if (
                self.platform.architecture
                in [
                    platforms.Architecture.MIPS32,
                    platforms.Architecture.MIPS64,
                ]
                and index == 0
            ):
                raise ConfigurationError(
                    f"Passing float as arg1 not currently supported for {self.platform}"
                )
            if self.platform.architecture == platforms.Architecture.X86_32:
                raise ConfigurationError(
                    f"Passing float not currently supported for {self.platform}"
                )

        # Get an argument out of a CStdModel or VariadicContext
        sp = self.platdef.sp_register
        on_stack = self._on_stack[index]
        arg_offset = self._arg_offset[index]
        kind = self.argument_types[index]

        if value < 0 and isinstance(value, int):
            # Negative value; need to find 2s-compliment if it's an int
            value *= -1
            if self.return_type in self._four_byte_types:
                value = ((value ^ self._int_inv_mask) + 1) & self._int_inv_mask
            elif self.return_type in self._eight_byte_types:
                value = (
                    (value ^ self._long_long_inv_mask) + 1
                ) & self._long_long_inv_mask
            else:
                # Unsigned type; why are you passing a negative?
                raise exceptions.ConfigurationError("Tried to pass a signed value")

        if kind in self._four_byte_types:
            if not isinstance(value, int):
                raise ConfigurationError(
                    f"Expected 4-byte integer value for argument {index}."
                )
            # Four byte integer
            if on_stack:
                # Stored on the stack; write to memory
                addr = emulator.read_register(sp) + arg_offset
                if self.platform.byteorder == Byteorder.BIG:
                    as_bytes = int.to_bytes(value, 4, "big")
                else:
                    as_bytes = int.to_bytes(value, 4, "little")
                emulator.write_memory(addr, as_bytes)
            else:
                # Stored in a register
                emulator.write_register(self._four_byte_arg_regs[arg_offset], value)

        elif kind in self._eight_byte_types:
            if not isinstance(value, int):
                raise ConfigurationError(
                    f"Expected 8-byte integer value for argument {index}."
                )
            # Eight byte integer
            if on_stack:
                # Stored on the stack; write to memory
                addr = emulator.read_register(sp) + arg_offset
                if self.platform.byteorder == Byteorder.BIG:
                    as_bytes = int.to_bytes(value, 8, "big")
                else:
                    as_bytes = int.to_bytes(value, 8, "little")
                emulator.write_memory(addr, as_bytes)
            elif self._eight_byte_reg_size == 2:
                # Stored in a register pair
                lo = value & self._int_inv_mask
                hi = (value >> 32) & self._int_inv_mask
                if self.platform.byteorder == Byteorder.BIG:
                    tmp = lo
                    lo = hi
                    hi = tmp
                emulator.write_register(self._eight_byte_arg_regs[arg_offset], lo)
                emulator.write_register(self._eight_byte_arg_regs[arg_offset + 1], hi)
            else:
                # Stored in a single register
                emulator.write_register(self._eight_byte_arg_regs[arg_offset], value)

        elif kind == ArgumentType.FLOAT:
            # Pack the bits
            if not isinstance(value, float):
                raise ConfigurationError(
                    f"Expected 4-byte float value for argument {index}."
                )
            if self.platform.byteorder == Byteorder.BIG:
                if self._floats_are_doubles:
                    as_bytes = struct.pack(">d", value)
                else:
                    as_bytes = struct.pack(">f", value)
                as_int = int.from_bytes(as_bytes, "big")
            else:
                if self._floats_are_doubles:
                    as_bytes = struct.pack("<d", value)
                else:
                    as_bytes = struct.pack("<f", value)
                as_int = int.from_bytes(as_bytes, "little")

            # Four-byte float
            if on_stack:
                # Stored on the stack
                addr = emulator.read_register(sp) + arg_offset
                emulator.write_memory(addr, as_bytes)
            elif self._soft_float:
                # Soft-float ABI; treat as a four-byte int
                emulator.write_register(self._four_byte_arg_regs[arg_offset], as_int)
            else:
                # Hard-float ABI; fetch from FPU registers
                emulator.write_register(self._float_arg_regs[arg_offset], as_int)

        elif kind == ArgumentType.DOUBLE:
            if not isinstance(value, float):
                raise ConfigurationError(
                    f"Expected 8-byte float value for argument {index}."
                )
            if self.platform.byteorder == Byteorder.BIG:
                as_bytes = struct.pack(">d", value)
                as_int = int.from_bytes(as_bytes, "big")
            else:
                as_bytes = struct.pack("<d", value)
                as_int = int.from_bytes(as_bytes, "little")

            # Eight-byte double float
            if on_stack:
                # Stored on the stack
                addr = emulator.read_register(sp) + arg_offset
                emulator.write_memory(addr, as_bytes)
            else:
                if self._soft_float:
                    # Soft-float ABI; treated as an eight-byte int
                    reg_array = self._eight_byte_arg_regs
                    n_regs = self._eight_byte_reg_size
                else:
                    # Hard-float ABI; stored in FPU registers
                    reg_array = self._double_arg_regs
                    n_regs = self._double_reg_size

                if n_regs == 2:
                    # Register pair.  Possible for both soft and hard floats.
                    lo = as_int & self._int_inv_mask
                    hi = (as_int >> 32) & self._int_inv_mask
                    if self.platform.byteorder == Byteorder.BIG:
                        tmp = lo
                        lo = hi
                        hi = tmp
                    emulator.write_register(reg_array[arg_offset], lo)
                    emulator.write_register(reg_array[arg_offset + 1], hi)
                else:
                    # Single register
                    emulator.write_register(reg_array[arg_offset], as_int)
        else:
            raise exceptions.ConfigurationError(
                f"Argument {index} has unknown type {kind}"
            )

    def get_argument(
        self: typing.Union["CStdCallingContext", "VariadicContext"],
        index: int,
        kind: ArgumentType,
        emulator: emulators.Emulator,
    ) -> typing.Union[int, float]:
        # Get an argument out of a CStdModel or VariadicContext
        sp = self.platdef.sp_register
        on_stack = self._on_stack[index]
        arg_offset = self._arg_offset[index]

        if kind in self._four_byte_types:
            # Four byte integer
            if on_stack:
                # Stored on the stack; read from memory
                addr = emulator.read_register(sp) + arg_offset
                data = emulator.read_memory(addr, self._four_byte_stack_size)
                if self.platform.byteorder == Byteorder.BIG:
                    intval = int.from_bytes(data, "big")
                else:
                    intval = int.from_bytes(data, "little")
            else:
                # Stored in a register
                intval = emulator.read_register(self._four_byte_arg_regs[arg_offset])

            # Handle integer signing and signedness
            # SmallWorld registers are unsigned, so we'll need to convert.
            # Some architectures zero-extend their integers, so we need to mask.
            intval = intval & self._int_inv_mask
            if kind in signed_int_types and (intval & self._int_sign_mask) != 0:
                intval = (intval ^ self._int_inv_mask) + 1
                intval *= -1
            return intval

        elif kind in self._eight_byte_types:
            # Eight byte integer
            if on_stack:
                # Stored on the stack
                addr = emulator.read_register(sp) + arg_offset
                data = emulator.read_memory(addr, self._eight_byte_stack_size)
                if self.platform.byteorder == Byteorder.BIG:
                    intval = int.from_bytes(data, "big")
                else:
                    intval = int.from_bytes(data, "little")
            elif self._eight_byte_reg_size == 2:
                # Stored in a register pair
                lo = emulator.read_register(self._eight_byte_arg_regs[arg_offset])
                hi = emulator.read_register(self._eight_byte_arg_regs[arg_offset + 1])
                if self.platform.byteorder == Byteorder.BIG:
                    tmp = lo
                    lo = hi
                    hi = tmp
                intval = (hi << 32) | lo
            else:
                # Stored in a single register
                intval = emulator.read_register(self._eight_byte_arg_regs[arg_offset])

            # Handle signedness
            # SmallWorld registers are unsigned, so we'll need to convert.
            if kind in signed_int_types and (intval & self._long_long_sign_mask) != 0:
                intval = (intval ^ self._long_long_inv_mask) + 1
                intval *= -1
            return intval
        elif kind == ArgumentType.FLOAT:
            # Four-byte float
            if on_stack:
                # Stored on the stack
                addr = emulator.read_register(sp) + arg_offset
                data = emulator.read_memory(addr, self._float_stack_size)
                if self.platform.byteorder == Byteorder.BIG:
                    intval = int.from_bytes(data, "big")
                else:
                    intval = int.from_bytes(data, "little")
            elif self._soft_float:
                # Soft-float ABI; treat as a four-byte int
                intval = emulator.read_register(self._four_byte_arg_regs[arg_offset])
            else:
                # Hard-float ABI; fetch from FPU registers
                intval = emulator.read_register(self._float_arg_regs[arg_offset])

            # Unpack the bits into a Python float
            # SmallWorld already did the work of converting endianness.
            if self._floats_are_doubles:
                # Some ABIs promote floats to doubles.
                # And by "some ABIs", I mean PowerPC.
                byteval = intval.to_bytes(8, "little")
                (floatval,) = struct.unpack("<d", byteval)
            else:
                byteval = (intval & self._int_inv_mask).to_bytes(4, "little")
                (floatval,) = struct.unpack("<f", byteval)
            return floatval
        elif kind == ArgumentType.DOUBLE:
            # Eight-byte double float
            if on_stack:
                # Stored on the stack
                addr = emulator.read_register(sp) + arg_offset
                data = emulator.read_memory(addr, self._double_stack_size)
                if self.platform.byteorder == Byteorder.BIG:
                    intval = int.from_bytes(data, "big")
                else:
                    intval = int.from_bytes(data, "little")
            else:
                if self._soft_float:
                    # Soft-float ABI; treated as an eight-byte int
                    reg_array = self._eight_byte_arg_regs
                    n_regs = self._eight_byte_reg_size
                else:
                    # Hard-float ABI; stored in FPU registers
                    reg_array = self._double_arg_regs
                    n_regs = self._double_reg_size

                if n_regs == 2:
                    # Register pair.  Possible for both soft and hard floats.
                    lo = emulator.read_register(reg_array[arg_offset])
                    hi = emulator.read_register(reg_array[arg_offset + 1])
                    if self.platform.byteorder == Byteorder.BIG:
                        tmp = lo
                        lo = hi
                        hi = tmp
                    intval = (hi << 32) | lo
                else:
                    # Single register
                    intval = emulator.read_register(reg_array[arg_offset])

            # Convert bits into Python float
            # SmallWorld already did the work of converting endianness.
            byteval = intval.to_bytes(8, "little")
            (floatval,) = struct.unpack("<d", byteval)
            return floatval
        else:
            raise exceptions.ConfigurationError(
                f"Argument {index} has unknown type {kind}"
            )

    def get_arg1(self, emulator: emulators.Emulator) -> typing.Union[int, float]:
        """Fetch the first argument from the emulator"""
        return self.get_argument(0, self.argument_types[0], emulator)

    def get_arg2(self, emulator: emulators.Emulator) -> typing.Union[int, float]:
        """Fetch the second argument from the emulator"""
        return self.get_argument(1, self.argument_types[1], emulator)

    def get_arg3(self, emulator: emulators.Emulator) -> typing.Union[int, float]:
        """Fetch the first argument from the emulator"""
        return self.get_argument(2, self.argument_types[2], emulator)

    def get_arg4(self, emulator: emulators.Emulator) -> typing.Union[int, float]:
        """Fetch the first argument from the emulator"""
        return self.get_argument(3, self.argument_types[3], emulator)

    def get_arg5(self, emulator: emulators.Emulator) -> typing.Union[int, float]:
        """Fetch the first argument from the emulator"""
        return self.get_argument(4, self.argument_types[4], emulator)

    def get_arg6(self, emulator: emulators.Emulator) -> typing.Union[int, float]:
        """Fetch the first argument from the emulator"""
        return self.get_argument(5, self.argument_types[5], emulator)

    def get_varargs(self) -> "VariadicContext":
        """Get a variadic argument context to fetch varargs

        Also necessary to handle more than six arguments.
        """
        return VariadicContext(self)

    def set_return_value(
        self, emulator: emulators.Emulator, val: typing.Union[int, float]
    ) -> None:
        """Return according to the appropriate return type"""
        if self.return_type == ArgumentType.VOID:
            # We're void.  You can't return from void.
            raise exceptions.ConfigurationError("Returning from void function")

        if self.return_type == ArgumentType.FLOAT:
            # We're a float.
            if not isinstance(val, float):
                raise exceptions.ConfigurationError(
                    f"Trying to return {type(val)} as a float"
                )
            self._return_float(emulator, val)
            return

        if self.return_type == ArgumentType.DOUBLE:
            # We're a double
            if not isinstance(val, float):
                raise exceptions.ConfigurationError(
                    f"Trying to return {type(val)} as a double"
                )
            self._return_double(emulator, val)
            return

        # All other types are integral
        if not isinstance(val, int):
            raise exceptions.ConfigurationError(
                f"Trying to return {type(val)} as an integral type"
            )

        if val < 0:
            # Negative value; need to find 2s-compliment if it's an int
            val *= -1
            if self.return_type in self._four_byte_types:
                val = ((val ^ self._int_inv_mask) + 1) & self._int_inv_mask
            elif self.return_type in self._eight_byte_types:
                val = ((val ^ self._long_long_inv_mask) + 1) & self._long_long_inv_mask
            elif (
                self.return_type == ArgumentType.FLOAT
                or self.return_type == ArgumentType.DOUBLE
            ):
                # Floating-point type; encoding will take care of this.
                pass
            else:
                # Unsigned type; why are you returning a negative?
                raise exceptions.ConfigurationError("Tried to return a signed value")

        # Delegate return to handler
        if self.return_type in self._four_byte_types:
            self._return_4_byte(emulator, val)

        elif self.return_type in self._eight_byte_types:
            self._return_8_byte(emulator, val)

        else:
            raise exceptions.ConfigurationError(
                f"Returning unhandled type {self.return_type}"
            )

    def get_return_value(self, emulator: emulators.Emulator) -> int | float | None:
        """Get return value, according to the appropriate return type"""
        if self.return_type == ArgumentType.VOID:
            # We're void.
            return None

        if self.return_type == ArgumentType.FLOAT:
            # We're a float.
            ret = self._read_return_float(emulator)
            return ret

        if self.return_type == ArgumentType.DOUBLE:
            # We're a double.
            ret = self._read_return_double(emulator)
            return ret

        if self.return_type in self._four_byte_types:
            ret = self._read_return_4_byte(emulator)
            if (
                self.return_type in signed_int_types
                and (ret & self._int_sign_mask) != 0
            ):
                ret = (ret ^ self._int_inv_mask) + 1
                ret *= -1
            return ret

        if self.return_type in self._eight_byte_types:
            ret = self._read_return_8_byte(emulator)
            if (
                self.return_type in signed_int_types
                and (ret & self._long_long_sign_mask) != 0
            ):
                ret = (ret ^ self._long_long_inv_mask) + 1
                ret *= -1
            return ret

        raise exceptions.ConfigurationError(
            f"Cannot read unhandled return type {self.return_type}"
        )

    def set_return_address(
        self, emulator: emulators.Emulator, address: int, push=False
    ) -> None:
        """Overwrite the return address of this model, or push a return address to the stack."""

        if self.platform.architecture == platforms.Architecture.X86_32:
            # i386: overwrite a 4-byte value on the stack
            sp = emulator.read_register("esp")
            if push:
                sp -= 4
                emulator.write_register("esp", sp)
            if self.platform.byteorder == platforms.Byteorder.LITTLE:
                as_bytes = int.to_bytes(address, 4, "little")
            elif self.platform.byteorder == platforms.Byteorder.BIG:
                as_bytes = int.to_bytes(address, 4, "big")
            emulator.write_memory(sp, as_bytes)
        elif self.platform.architecture == platforms.Architecture.X86_64:
            # amd64: overwrite an 8-byte value on the stack
            sp = emulator.read_register("rsp")
            if push:
                sp -= 8
                emulator.write_register("rsp", sp)
            if self.platform.byteorder == platforms.Byteorder.LITTLE:
                as_bytes = int.to_bytes(address, 8, "little")
            elif self.platform.byteorder == platforms.Byteorder.BIG:
                as_bytes = int.to_bytes(address, 8, "big")
            emulator.write_memory(sp, as_bytes)
        elif (
            self.platform.architecture == platforms.Architecture.AARCH64
            or self.platform.architecture == platforms.Architecture.ARM_V5T
            or self.platform.architecture == platforms.Architecture.ARM_V6M
            or self.platform.architecture == platforms.Architecture.ARM_V6M_THUMB
            or self.platform.architecture == platforms.Architecture.ARM_V7A
            or self.platform.architecture == platforms.Architecture.ARM_V7M
            or self.platform.architecture == platforms.Architecture.ARM_V7R
            or self.platform.architecture == platforms.Architecture.POWERPC32
            or self.platform.architecture == platforms.Architecture.POWERPC64
        ):
            # aarch64, arm32, powerpc and powerpc64: branch to register 'lr'
            emulator.write_register("lr", address)
        elif (
            self.platform.architecture == platforms.Architecture.LOONGARCH64
            or self.platform.architecture == platforms.Architecture.MIPS32
            or self.platform.architecture == platforms.Architecture.MIPS64
            or self.platform.architecture == platforms.Architecture.RISCV64
        ):
            # mips32, mips64, and riscv64: branch to register 'ra'
            emulator.write_register("ra", address)
        elif self.platform.architecture == platforms.Architecture.XTENSA:
            # xtensa: branch to register 'a0'
            emulator.write_register("a0", address)
        else:
            raise exceptions.ConfigurationError(
                "Don't know how to return for {self.platform.architecture}"
            )


class CStdModel(Model, CStdCallingContext):
    """Base class for C standard function models


    Regardless of which version of a library you use,
    all "true" C functions will use the same interface
    defined by the ABI.
    (There are exceptions, such as thunks and internal functions
    never intended for human eyes)

    This abstracts away the ABI-specific operations
    performed by a function, namely getting args and returning vals.

    This also includes a parameterizable calling convention model.
    Every calling convention I've seen fits into a kind
    of Grand Unifying Theory.  They all pass a certain
    number of arguments via registers before switching to stack,
    and handle different-sized integers or floats
    in a few standard ways.

    It was way easier to figure out this theory and write one model
    than to maintain eleven-plus separate models.
    This may break for particularly unusual architectures,
    or very strange ABIs.  For living architectures
    with Debian support (sorry, hppa), it works.
    """

    def __init__(self, address: int):
        super().__init__(address)
        CStdCallingContext.__init__(self)
        self.platdef = PlatformDef.for_platform(self.platform)

    def read_integer(
        self, address: int, kind: ArgumentType, emulator: emulators.Emulator
    ) -> int:
        """Read an integer out of memory based on type

        Arguments:
            address: The address to read from
            kind: The ArgumentType to read
            emulator: The emulator to read from
        """
        if kind in (ArgumentType.CHAR, ArgumentType.UCHAR):
            width = 1
        elif kind in (ArgumentType.SHORT, ArgumentType.USHORT):
            width = 2
        elif kind in (ArgumentType.INT, ArgumentType.UINT):
            width = 4
        elif kind in (ArgumentType.LONG, ArgumentType.ULONG, ArgumentType.POINTER):
            width = 4 if ArgumentType.LONG in self._four_byte_types else 8
        elif kind in (ArgumentType.LONGLONG, ArgumentType.ULONGLONG):
            width = 8

        byteval = emulator.read_memory(address, width)

        if self.platform.byteorder == Byteorder.LITTLE:
            return int.from_bytes(byteval, "little")
        else:
            return int.from_bytes(byteval, "big")

    def write_integer(
        self,
        address: int,
        intval: int,
        kind: ArgumentType,
        emulator: emulators.Emulator,
    ) -> None:
        """Write an integer based on type

        Note that this will handle converting signed to bytes.

        Arguments:
            address: The address to write to
            intval: The integer value to write
            kind: The ArgumentType to write
            emulator: The emulator to write to
        """
        if intval < 0:
            intval *= -1
            intval = (intval ^ self._long_long_inv_mask) + 1

        if kind in (ArgumentType.CHAR, ArgumentType.UCHAR):
            intval &= self._char_inv_mask
            width = 1
        elif kind in (ArgumentType.SHORT, ArgumentType.USHORT):
            intval &= self._short_inv_mask
            width = 2
        elif kind in (ArgumentType.INT, ArgumentType.UINT):
            intval &= self._int_inv_mask
            width = 4
        elif kind in (ArgumentType.LONG, ArgumentType.ULONG, ArgumentType.POINTER):
            intval &= self._long_inv_mask
            width = 4 if ArgumentType.LONG in self._four_byte_types else 8
        elif kind in (ArgumentType.LONGLONG, ArgumentType.ULONGLONG):
            intval &= self._long_long_inv_mask
            width = 8

        if self.platform.byteorder == Byteorder.LITTLE:
            byteval = intval.to_bytes(width, "little")
        else:
            byteval = intval.to_bytes(width, "big")

        emulator.write_memory(address, byteval)


class VariadicContext:
    """Context for extracting variadic arguments

    Variadic functions extend the argument list at runtime.
    Handling this requires dynamically updating the
    list of arguments.  I'd rather do this on a throw-away object
    than on a Model object that will have to reset itself
    for multiple invocations.

    """

    def __init__(self, parent: CStdCallingContext) -> None:
        self.parent = parent
        self.platform = parent.platform
        self.platdef = parent.platdef

        # Copy the calling convention specification from the parent
        # It's this, or slow the interpreter down by using properties.
        self._int_sign_mask = parent._int_sign_mask
        self._int_inv_mask = parent._int_inv_mask
        self._long_sign_mask = parent._long_sign_mask
        self._long_inv_mask = parent._long_inv_mask
        self._long_long_sign_mask = parent._long_long_sign_mask
        self._long_long_inv_mask = parent._long_long_inv_mask

        self._four_byte_types = parent._four_byte_types
        self._eight_byte_types = parent._eight_byte_types
        self._four_byte_arg_regs = parent._four_byte_arg_regs
        self._eight_byte_arg_regs = parent._eight_byte_arg_regs
        self._soft_float = parent._soft_float or parent._variadic_soft_float
        self._floats_are_doubles = parent._floats_are_doubles
        self._float_arg_regs = parent._float_arg_regs
        self._double_arg_regs = parent._double_arg_regs
        self._init_stack_offset = parent._init_stack_offset
        self._align_stack = parent._align_stack
        self._eight_byte_reg_size = parent._eight_byte_reg_size
        self._double_reg_size = parent._double_reg_size
        self._four_byte_stack_size = parent._four_byte_stack_size
        self._eight_byte_stack_size = parent._eight_byte_stack_size
        self._float_stack_size = parent._float_stack_size
        self._double_stack_size = parent._double_stack_size

        # Copy the parent's current argument state
        self._int_reg_offset = parent._int_reg_offset
        self._fp_reg_offset = parent._fp_reg_offset
        self._stack_offset = parent._stack_offset

        self._on_stack = parent._on_stack.copy()
        self._arg_offset = parent._arg_offset.copy()

    def get_next_argument(
        self, kind: ArgumentType, emulator: emulators.Emulator
    ) -> typing.Union[int, float]:
        """Get the next argument of an assumed type"""
        index = len(self._on_stack)

        CStdCallingContext.add_argument(self, index, kind)
        return CStdCallingContext.get_argument(self, index, kind, emulator)
