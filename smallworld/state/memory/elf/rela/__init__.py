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
from .loongarch import LoongArch32ElfRelocator, LoongArch64ElfRelocator
from .m68k import M68KElfRelocator
from .mips import MIPSELElfRelocator, MIPSElfRelocator
from .ppc import PowerPCElfRelocator, PowerPCVLEElfRelocator
from .rela import ElfRelocator
from .riscv32 import RISCV32ElfRelocator
from .riscv64 import RISCV64ElfRelocator
from .superh import (
    SH2AFPUElfRelocator,
    SuperH4BEElfRelocator,
    SuperH4ELElfRelocator,
    SuperHElfRelocator,
)
from .tricore import TriCoreElfRelocator
from .v850 import V850ElfRelocator
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
    "LoongArch32ElfRelocator",
    "LoongArch64ElfRelocator",
    "M68KElfRelocator",
    "MIPSElfRelocator",
    "MIPSELElfRelocator",
    "PowerPCElfRelocator",
    "RISCV32ElfRelocator",
    "PowerPCVLEElfRelocator",
    "RISCV64ElfRelocator",
    "SH2AFPUElfRelocator",
    "SuperH4BEElfRelocator",
    "SuperH4ELElfRelocator",
    "SuperHElfRelocator",
    "TriCoreElfRelocator",
    "V850ElfRelocator",
    "XtensaElfRelocator",
    "ElfRelocator",
]
