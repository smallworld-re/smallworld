from .aarch64 import AArch64ElfRelocator
from .amd64 import AMD64ElfRelocator
from .arm import (
    Armv5TElfRelocator,
    Armv6MElfRelocator,
    Armv7AElfRelocator,
    Armv7MElfRelocator,
    Armv7RElfRelocator,
)
from .rela import ElfRelocator

__all__ = [
    "AArch64ElfRelocator",
    "AMD64ElfRelocator",
    "Armv5TElfRelocator",
    "Armv6MElfRelocator",
    "Armv7AElfRelocator",
    "Armv7MElfRelocator",
    "Armv7RElfRelocator",
    "ElfRelocator",
]
