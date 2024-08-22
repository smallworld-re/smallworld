import enum
from dataclasses import dataclass


class Architecture(enum.Enum):
    """Architecture and mode.

    Names take the form ``{ARCH}_{MODE}`` where ``{ARCH}`` and ``{MODE}``
    match the regex ``[A-Z0-9]+``.

    Values are lowercase, kebab-case.
    """

    X86_32 = "x86-32"
    """32-bit x86."""

    X86_64 = "x86-64"
    """64-bit x86."""


class Byteorder(enum.Enum):
    """Endianness."""

    BIG = "big"
    """Big endian - most significant bit first."""

    LITTLE = "little"
    """Little endian - least significant bit first."""

    MIDDLE = "middle"
    """Middle endian - also known as PDP-endian."""


class ABI(enum.Enum):
    """Application binary interface.

    Names match the regex ``[A-Z]+``.

    Values are lowercase, kebab-case.
    """

    SYSTEMV = "system-v"
    """System V."""

    CDECL = "cdecl"
    """Microsoft cdecl."""

    VECTORCALL = "vectorcall"
    """Microsoft vectorcall."""

    FASTCALL = "fastcall"
    """Microsoft fastcall."""


@dataclass(frozen=True)
class Platform:
    """Platform metadata/configuration storage class."""

    architecture: Architecture
    """Architecture and mode."""

    byteorder: Byteorder
    """Endianness."""

    abi: ABI
    """Application binary inteface."""


__all__ = ["Platform", "Architecture", "Byteorder", "ABI"]
