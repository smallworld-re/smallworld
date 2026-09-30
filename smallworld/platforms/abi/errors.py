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
    checkout that has not run the generator has none. They are loaded once,
    when :mod:`smallworld.platforms.abi` is imported; that import never
    raises because of them, and records why they did not load instead. Every
    registry lookup then raises this, with that reason as its message,
    instead of answering "not modelled", so a missing install step is never
    mistaken for a platform without an ABI record.
    """

    pass


class ABITablesStale(UserWarning):
    """The installed ABI tables are older than the sources they came from.

    An editable build on a Python that generates no tables (3.9, 3.11) keeps
    the tables an earlier build wrote; when the overlay or the generator has
    changed since, the tables carry a ``STALE`` note and loading them warns.
    Regenerate them with ``python tools/abi/generate.py --inplace`` on Python
    3.10 or 3.12+.
    """


__all__ = [
    "ABITablesStale",
    "ABITablesUnavailable",
    "UnrealizableLocation",
    "UnsupportedSignature",
]
