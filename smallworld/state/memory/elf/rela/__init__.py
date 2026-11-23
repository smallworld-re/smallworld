from .aarch64 import (
    AArch64BEElfRelocator,
    AArch64ElfRelocator,
    AArch64V85ABEElfRelocator,
    AArch64V85AElfRelocator,
)
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
from .loongarch import LoongArch32ElfRelocator, LoongArch64ElfRelocator
from .m68k import M68KElfRelocator
from .mips import MIPSELElfRelocator, MIPSElfRelocator
from .ppc import PowerPCElfRelocator, PowerPCVLEElfRelocator
from .rela import ElfRelocator
from .riscv32 import RISCV32ElfRelocator
from .riscv64 import RISCV64ElfRelocator
from .sparc import SPARC32ElfRelocator
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
    "AArch64BEElfRelocator",
    "AArch64V85AElfRelocator",
    "AArch64V85ABEElfRelocator",
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
    "SPARC32ElfRelocator",
    "SuperH4BEElfRelocator",
    "SuperH4ELElfRelocator",
    "SuperHElfRelocator",
    "TriCoreElfRelocator",
    "V850ElfRelocator",
    "XtensaElfRelocator",
    "ElfRelocator",
]
