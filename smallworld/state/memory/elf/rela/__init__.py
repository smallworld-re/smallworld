from .aarch64 import AArch64BEElfRelocator, AArch64ElfRelocator
from .amd64 import AMD64ElfRelocator
from .arm import (
    Armv4BEElfRelocator,
    Armv4ElfRelocator,
    Armv4TBEElfRelocator,
    Armv4TElfRelocator,
    Armv5TBEElfRelocator,
    Armv5TElfRelocator,
    Armv6MElfRelocator,
    Armv7AElfRelocator,
    Armv7EMElfRelocator,
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
from .superh import SH2AFPUElfRelocator, SuperH4BEElfRelocator, SuperH4ELElfRelocator
from .tricore import TriCoreElfRelocator
from .xtensa import XtensaElfRelocator

__all__ = [
    "AArch64ElfRelocator",
    "AArch64BEElfRelocator",
    "AMD64ElfRelocator",
    "Armv4ElfRelocator",
    "Armv4TElfRelocator",
    "Armv5TElfRelocator",
    "Armv4BEElfRelocator",
    "Armv4TBEElfRelocator",
    "Armv5TBEElfRelocator",
    "Armv6MElfRelocator",
    "Armv7AElfRelocator",
    "Armv7EMElfRelocator",
    "Armv7MElfRelocator",
    "Armv7RElfRelocator",
    "I386ElfRelocator",
    "LoongArch64ElfRelocator",
    "M68KElfRelocator",
    "MIPSElfRelocator",
    "MIPSELElfRelocator",
    "PowerPCElfRelocator",
    "RISCV64ElfRelocator",
    "SH2AFPUElfRelocator",
    "SuperH4BEElfRelocator",
    "SuperH4ELElfRelocator",
    "TriCoreElfRelocator",
    "XtensaElfRelocator",
    "ElfRelocator",
]
