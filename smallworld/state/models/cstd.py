import abc
import enum
import typing

from ... import emulators, exceptions
from .model import Model


class ArgumentType(enum.Enum):
    """C primitive data types for specifying function arguments.

    The exact size of these types depends strongly on the ABI.
    These specify the source-level signature;
    the ABI-specific subclasses of CStdModel figure out how to decode them.
    """

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


class CStdModel(Model):
    """Base class for C standard function models


    Regardless of which version of a library you use,
    all "true" C functions will use the same interface
    defined by the ABI.
    (There are exceptions, such as thunks and internal functions
    never intended for human eyes)

    This abstracts away the ABI-specific operations
    performed by a function, namely getting args and returning vals.

    Annoyingly, many ABIs don't have an easy one-to-one mapping
    from "arg i" to a specific part of the machine state,
    and location can change depending on the function's signature.
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

    def __init__(self, address: int):
        super().__init__(address)
        # Set this to True to bypass the "imprecise" flag.
        self.allow_imprecise = False

    def model(self, emulator: emulators.Emulator):
        if self.imprecise and not self.allow_imprecise:
            raise exceptions.ConfigurationError(
                f"Invoked model for {self.name}, which is imprecise"
            )

    @abc.abstractmethod
    def _get_argument(
        self,
        index: int,
        kind: ArgumentType,
        emulator: emulators.Emulator,
        absolute: bool = False,
    ) -> typing.Union[int, float]:
        """Fetch the index'th argument given the argument types and the ABI."""
        raise NotImplementedError()

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
        return self._get_argument(0, self.argument_types[0], emulator)

    def get_arg2(self, emulator: emulators.Emulator) -> typing.Union[int, float]:
        """Fetch the second argument from the emulator"""
        return self._get_argument(1, self.argument_types[1], emulator)

    def get_arg3(self, emulator: emulators.Emulator) -> typing.Union[int, float]:
        """Fetch the first argument from the emulator"""
        return self._get_argument(2, self.argument_types[2], emulator)

    def get_arg4(self, emulator: emulators.Emulator) -> typing.Union[int, float]:
        """Fetch the first argument from the emulator"""
        return self._get_argument(3, self.argument_types[3], emulator)

    def get_arg5(self, emulator: emulators.Emulator) -> typing.Union[int, float]:
        """Fetch the first argument from the emulator"""
        return self._get_argument(4, self.argument_types[4], emulator)

    def get_arg6(self, emulator: emulators.Emulator) -> typing.Union[int, float]:
        """Fetch the first argument from the emulator"""
        return self._get_argument(5, self.argument_types[5], emulator)

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
            if not isinstance(val, float):
                raise exceptions.ConfigurationError(
                    f"{self.name} trying to return {type(val)} as a float"
                )
            self._return_float(emulator, val)
            return

        if self.return_type == ArgumentType.DOUBLE:
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
