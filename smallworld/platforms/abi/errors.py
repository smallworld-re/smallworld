"""Exceptions raised by :mod:`smallworld.platforms.abi`."""

from ...exceptions.exceptions import ConfigurationError


class UnrealizableLocation(ConfigurationError):
    """An ABI location cannot be represented on the target.

    For example, the register is not modelled by the emulator, or the value's
    encoding (x87 80-bit) cannot be written through the available views.
    """

    pass


class UnsupportedSignature(ConfigurationError):
    """The ABI record cannot place this signature.

    Raised for signatures a record declares unsupported (aggregates by value,
    ``varargs=none`` records called variadically, and so on) rather than
    guessing a placement.
    """

    pass


class ABITablesUnavailable(ConfigurationError):
    """No ABI tables are installed, or the installed tables failed to load.

    The tables are generated when smallworld is built or installed; a source
    checkout that has not run the generator has none. Every registry lookup
    raises this instead of answering "not modelled", so a missing install step
    is never mistaken for a platform without an ABI record.
    """

    pass


__all__ = ["ABITablesUnavailable", "UnrealizableLocation", "UnsupportedSignature"]
