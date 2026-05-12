from .aarch64 import AArch64ElfRelocator
from .amd64 import AMD64ElfRelocator
from .arm import (
    Armv5TElfRelocator,
    Armv6MElfRelocator,
    Armv7AElfRelocator,
    Armv7MElfRelocator,
    Armv7RElfRelocator,
)
from .i386 import I386ElfRelocator
from .loongarch import LoongArch64ElfRelocator
from .m68k import M68KElfRelocator
from .mips import MIPSELElfRelocator, MIPSElfRelocator
from .ppc import PowerPCElfRelocator
from .rela import ElfRelocator
from .riscv64 import RISCV64ElfRelocator
from .tricore import TriCoreElfRelocator
from .xtensa import XtensaElfRelocator

__all__ = [
    "AArch64ElfRelocator",
    "AMD64ElfRelocator",
    "Armv5TElfRelocator",
    "Armv6MElfRelocator",
    "Armv7AElfRelocator",
    "Armv7MElfRelocator",
    "Armv7RElfRelocator",
    "I386ElfRelocator",
    "LoongArch64ElfRelocator",
    "M68KElfRelocator",
    "MIPSElfRelocator",
    "MIPSELElfRelocator",
    "PowerPCElfRelocator",
    "RISCV64ElfRelocator",
    "TriCoreElfRelocator",
    "XtensaElfRelocator",
    "ElfRelocator",
]
