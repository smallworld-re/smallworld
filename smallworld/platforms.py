import enum
from dataclasses import dataclass


class Architecture(enum.Enum):
    """Architecture and mode.

    Names take the form ``{ARCH}_{MODE}`` where ``{ARCH}`` and ``{MODE}``
    match the regex ``[A-Z0-9]+``.

    Values are lowercase, kebab-case.
    """

    X86_32 = "x86-32"
    """32-bit x86 supporting SSE extensions."""

    X86_64 = "x86-64"
    """64-bit x86 supporting AVX2 extensions."""

    X86_64_AVX512 = "x86-64-avx512"
    """64-bit x86 supporting AVX512 extensions."""

    AARCH64 = "aarch64"

    MIPS32 = "mips32"

    MIPS64 = "mips64"

    POWERPC64 = "powerpc64"
    POWERPC32 = "powerpc32"

    ARM_V5T = "arm-v5t"
    ARM_V6M = "arm-v6m"
    ARM_V6M_THUMB = "arm-v6m-thumb"
    ARM_V7M = "arm-v7m"
    ARM_V7R = "arm-v7r"
    ARM_V7A = "arm-v7a"

    RISCV64 = "riscv-64"

    XTENSA = "xtensa"


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

    NONE = "none"
    """No ABI"""


@dataclass(frozen=True)
class Platform:
    """Platform metadata/configuration storage class."""

    architecture: Architecture
    """Architecture and mode."""

    byteorder: Byteorder
    """Endianness."""

    def __repr__(self) -> str:
        return f"{self.architecture}:{self.byteorder}"


__all__ = ["Platform", "Architecture", "Byteorder", "ABI"]
