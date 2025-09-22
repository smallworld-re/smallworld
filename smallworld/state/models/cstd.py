import abc
import enum
import logging
import struct
import typing

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


def add_argument(
    i: int, kind: ArgumentType, model: typing.Union["CStdModel", "VariadicContext"]
):
    if kind in model._four_byte_types or (
        kind == ArgumentType.FLOAT and model._soft_float
    ):
        # Four byte int type, or float on a system without separate FP arg regs
        if model._int_reg_offset == len(model._four_byte_arg_regs):
            # No room left in registers; use stack
            model._on_stack.append(True)
            model._arg_offset.append(model._stack_offset + model._init_stack_offset)
            model._stack_offset += model._four_byte_stack_size
        else:
            # Registers left; use them
            model._on_stack.append(False)
            model._arg_offset.append(model._int_reg_offset)
            model._int_reg_offset += 1
    elif kind in model._eight_byte_types or (
        kind == ArgumentType.DOUBLE and model._soft_float
    ):
        # Eight byte int type, or double on a system without separate FP arg regs
        if model._int_reg_offset % model._eight_byte_reg_size != 0:
            # Align argument register for eight-byte value
            model._int_reg_offset += 1

        if model._int_reg_offset == len(model._eight_byte_arg_regs):
            # No room left in registers; use stack
            if (
                model._align_stack
                and model._stack_offset % model._eight_byte_stack_size != 0
            ):
                # Stack out of alignment.  Align it.
                model._stack_offset += 4
            model._on_stack.append(True)
            model._arg_offset.append(model._stack_offset + model._init_stack_offset)
            model._stack_offset += model._eight_byte_stack_size
        else:
            # Registers left; use them
            model._on_stack.append(False)
            model._arg_offset.append(model._int_reg_offset)
            model._int_reg_offset += model._eight_byte_reg_size
    elif kind == ArgumentType.FLOAT:
        # Float type
        if model._fp_reg_offset == len(model._float_arg_regs):
            # No room left in registers; use stack
            model._on_stack.append(True)
            model._arg_offset.append(model._stack_offset + model._init_stack_offset)
            model._stack_offset += model._float_stack_size
        else:
            # Registers left; use them
            model._on_stack.append(False)
            model._arg_offset.append(model._fp_reg_offset)
            model._fp_reg_offset += 1
    elif kind == ArgumentType.DOUBLE:
        # Double type
        if model._fp_reg_offset % model._double_reg_size != 0:
            model._fp_reg_offset += 1

        if model._fp_reg_offset == len(model._double_arg_regs):
            # No room left in registers; use stack
            if (
                model._align_stack
                and model._stack_offset % model._double_stack_size != 0
            ):
                model._stack_offset += 4
            model._on_stack.append(True)
            model._arg_offset.append(model._stack_offset + model._init_stack_offset)
            model._stack_offset += model._double_stack_size
        else:
            # Registers left; use them
            model._on_stack.append(False)
            model._arg_offset.append(model._fp_reg_offset)
            model._fp_reg_offset += model._double_reg_size
    else:
        raise exceptions.ConfigurationError(
            f"{model.name} argument {i} has unknown type {kind}"
        )


def get_argument(
    model: typing.Union["CStdModel", "VariadicContext"],
    index: int,
    kind: ArgumentType,
    emulator: emulators.Emulator,
) -> typing.Union[int, float]:
    # Get an argument out of a CStdModel or VariadicContext
    sp = model.platdef.sp_register
    on_stack = model._on_stack[index]
    arg_offset = model._arg_offset[index]

    if kind in model._four_byte_types:
        # Four byte integer
        if on_stack:
            # Stored on the stack; read from memory
            addr = emulator.read_register(sp) + arg_offset
            data = emulator.read_memory(addr, model._four_byte_stack_size)
            if model.platform.byteorder == Byteorder.BIG:
                intval = int.from_bytes(data, "big")
            else:
                intval = int.from_bytes(data, "little")
        else:
            # Stored in a register
            intval = emulator.read_register(model._four_byte_arg_regs[arg_offset])

        # Handle integer signing and signedness
        # SmallWorld registers are unsigned, so we'll need to convert.
        # Some architectures zero-extend their integers, so we need to mask.
        intval = intval & model._int_inv_mask
        if kind in signed_int_types and (intval & model._int_sign_mask) != 0:
            intval = (intval ^ model._int_inv_mask) + 1
            intval *= -1
        return intval

    elif kind in model._eight_byte_types:
        # Eight byte integer
        if on_stack:
            # Stored on the stack
            addr = emulator.read_register(sp) + arg_offset
            data = emulator.read_memory(addr, model._eight_byte_stack_size)
            if model.platform.byteorder == Byteorder.BIG:
                intval = int.from_bytes(data, "big")
            else:
                intval = int.from_bytes(data, "little")
        elif model._eight_byte_reg_size == 2:
            # Stored in a register pair
            lo = emulator.read_register(model._eight_byte_arg_regs[arg_offset])
            hi = emulator.read_register(model._eight_byte_arg_regs[arg_offset + 1])
            if model.platform.byteorder == Byteorder.BIG:
                tmp = lo
                lo = hi
                hi = tmp
            intval = (hi << 32) | lo
        else:
            # Stored in a single register
            intval = emulator.read_register(model._eight_byte_arg_regs[arg_offset])

        # Handle signedness
        # SmallWorld registers are unsigned, so we'll need to convert.
        if kind in signed_int_types and (intval & model._long_long_sign_mask) != 0:
            intval = (intval ^ model._long_long_inv_mask) + 1
            intval *= -1
        return intval
    elif kind == ArgumentType.FLOAT:
        # Four-byte float
        if on_stack:
            # Stored on the stack
            addr = emulator.read_register(sp) + arg_offset
            data = emulator.read_memory(addr, model._float_stack_size)
            if model.platform.byteorder == Byteorder.BIG:
                intval = int.from_bytes(data, "big")
            else:
                intval = int.from_bytes(data, "little")
        elif model._soft_float:
            # Soft-float ABI; treat as a four-byte int
            intval = emulator.read_register(model._four_byte_arg_regs[arg_offset])
        else:
            # Hard-float ABI; fetch from FPU registers
            intval = emulator.read_register(model._float_arg_regs[arg_offset])

        # Unpack the bits into a Python float
        # SmallWorld already did the work of converting endianness.
        if model._floats_are_doubles:
            # Some ABIs promote floats to doubles.
            # And by "some ABIs", I mean PowerPC.
            byteval = intval.to_bytes(8, "little")
            (floatval,) = struct.unpack("<d", byteval)
        else:
            byteval = (intval & model._int_inv_mask).to_bytes(4, "little")
            (floatval,) = struct.unpack("<f", byteval)
        return floatval
    elif kind == ArgumentType.DOUBLE:
        # Eight-byte double float
        if on_stack:
            # Stored on the stack
            addr = emulator.read_register(sp) + arg_offset
            data = emulator.read_memory(addr, model._double_stack_size)
            if model.platform.byteorder == Byteorder.BIG:
                intval = int.from_bytes(data, "big")
            else:
                intval = int.from_bytes(data, "little")
        else:
            if model._soft_float:
                # Soft-float ABI; treated as an eight-byte int
                reg_array = model._eight_byte_arg_regs
                n_regs = model._eight_byte_reg_size
            else:
                # Hard-float ABI; stored in FPU registers
                reg_array = model._double_arg_regs
                n_regs = model._double_reg_size

            if n_regs == 2:
                # Register pair.  Possible for both soft and hard floats.
                lo = emulator.read_register(reg_array[arg_offset])
                hi = emulator.read_register(reg_array[arg_offset + 1])
                if model.platform.byteorder == Byteorder.BIG:
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
            f"{model.name} argument {index} has unknown type {kind}"
        )


class CStdModel(Model):
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

    # Flag indicating this model is imprecise.
    #
    # Most models are assumed to be approximations,
    # but this model definitely doesn't capture
    # a critical behavior.
    #
    # By default, these models should raise an exception if called.
    # The user can accept the risk and run a placeholde version
    # by setting the attribute "allow_imprecise" to True.
    #
    # Authors probably shouldn't rely on this flag
    # to mark truly-unimplemented models;
    # just raise an exception yourself.
    imprecise = False

    @property
    @abc.abstractmethod
    def argument_types(self) -> typing.List[ArgumentType]:
        """List of argument types for this function

        NOTE: Don't include variadics.
        """
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def return_type(self) -> ArgumentType:
        """Return type for this function"""
        raise NotImplementedError()

    def __init__(self, address: int):
        super().__init__(address)

        self.platdef = PlatformDef.for_platform(self.platform)

        # Set this to True to bypass the "imprecise" flag.
        self.allow_imprecise = False

        self._int_reg_offset = 0
        self._fp_reg_offset = 0
        self._stack_offset = 0

        self._on_stack: typing.List[bool] = list()
        self._arg_offset: typing.List[int] = list()

        for i in range(0, len(self.argument_types)):
            t = self.argument_types[i]
            add_argument(i, t, self)

    def model(self, emulator: emulators.Emulator):
        if self.imprecise and not self.allow_imprecise:
            raise exceptions.ConfigurationError(
                f"Invoked model for {self.name}, which is imprecise"
            )

    @abc.abstractmethod
    def _return_4_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return a four-byte type"""
        raise NotImplementedError()

    @abc.abstractmethod
    def _return_8_byte(self, emulator: emulators.Emulator, val: int) -> None:
        """Return an eight-byte type"""
        raise NotImplementedError()

    @abc.abstractmethod
    def _return_float(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a float"""
        raise NotImplementedError()

    @abc.abstractmethod
    def _return_double(self, emulator: emulators.Emulator, val: float) -> None:
        """Return a double"""
        raise NotImplementedError()

    def get_arg1(self, emulator: emulators.Emulator) -> typing.Union[int, float]:
        """Fetch the first argument from the emulator"""
        return get_argument(self, 0, self.argument_types[0], emulator)

    def get_arg2(self, emulator: emulators.Emulator) -> typing.Union[int, float]:
        """Fetch the second argument from the emulator"""
        return get_argument(self, 1, self.argument_types[1], emulator)

    def get_arg3(self, emulator: emulators.Emulator) -> typing.Union[int, float]:
        """Fetch the first argument from the emulator"""
        return get_argument(self, 2, self.argument_types[2], emulator)

    def get_arg4(self, emulator: emulators.Emulator) -> typing.Union[int, float]:
        """Fetch the first argument from the emulator"""
        return get_argument(self, 3, self.argument_types[3], emulator)

    def get_arg5(self, emulator: emulators.Emulator) -> typing.Union[int, float]:
        """Fetch the first argument from the emulator"""
        return get_argument(self, 4, self.argument_types[4], emulator)

    def get_arg6(self, emulator: emulators.Emulator) -> typing.Union[int, float]:
        """Fetch the first argument from the emulator"""
        return get_argument(self, 5, self.argument_types[5], emulator)

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
            raise exceptions.ConfigurationError(
                f"{self.name} returning from void function"
            )

        if self.return_type == ArgumentType.FLOAT:
            # We're a float.
            if not isinstance(val, float):
                raise exceptions.ConfigurationError(
                    f"{self.name} trying to return {type(val)} as a float"
                )
            self._return_float(emulator, val)
            return

        if self.return_type == ArgumentType.DOUBLE:
            # We're a double
            if not isinstance(val, float):
                raise exceptions.ConfigurationError(
                    f"{self.name} trying to return {type(val)} as a double"
                )
            self._return_double(emulator, val)
            return

        # All other types are integral
        if not isinstance(val, int):
            raise exceptions.ConfigurationError(
                f"{self.name} trying to return {type(val)} as an integral type"
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
                raise exceptions.ConfigurationError(
                    f"{self.name} tried to return a signed value"
                )

        # Delegate return to handler
        if self.return_type in self._four_byte_types:
            self._return_4_byte(emulator, val)

        elif self.return_type in self._eight_byte_types:
            self._return_8_byte(emulator, val)

        else:
            raise exceptions.ConfigurationError(
                f"{self.name} returning unhandled type {self.return_type}"
            )

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


class VariadicContext:
    """Context for extracting variadic arguments

    Variadic functions extend the argument list at runtime.
    Handling this requires dynamically updating the
    list of arguments.  I'd rather do this on a throw-away object
    than on a Model object that will have to reset itself
    for multiple invocations.

    """

    def __init__(self, parent: CStdModel) -> None:
        self.name = parent.name
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

        add_argument(index, kind, self)
        return get_argument(self, index, kind, emulator)
