from .aarch64 import AArch64MachineDef
from .amd64 import AMD64MachineDef
from .arm import (
    ARMv5TMachineDef,
    ARMv6MMachineDef,
    ARMv6MThumbMachineDef,
    ARMv7AMachineDef,
    ARMv7MMachineDef,
    ARMv7RMachineDef,
)
from .i386 import i386MachineDef
from .m68k import M68KMachineDef
from .machdef import UnicornMachineDef
from .mips import (
    MicroMIPSBEMachineDef,
    MicroMIPSELMachineDef,
    MIPS64BEMachineDef,
    MIPS64ELMachineDef,
    MIPSBEMachineDef,
    MIPSELMachineDef,
)
from .ppc import PPC32MachineDef, PPC64MachineDef
from .riscv64 import RISCV32MachineDef, RISCV64MachineDef
from .tricore import TriCoreMachineDef
from .x86_16 import X86RealModeMachineDef

__all__ = [
    "AArch64MachineDef",
    "AMD64MachineDef",
    "ARMv5TMachineDef",
    "ARMv6MMachineDef",
    "ARMv6MThumbMachineDef",
    "ARMv7AMachineDef",
    "ARMv7MMachineDef",
    "ARMv7RMachineDef",
    "i386MachineDef",
    "M68KMachineDef",
    "MIPSBEMachineDef",
    "MIPSELMachineDef",
    "MIPS64BEMachineDef",
    "MIPS64ELMachineDef",
    "MicroMIPSBEMachineDef",
    "MicroMIPSELMachineDef",
    "PPC32MachineDef",
    "PPC64MachineDef",
    "RISCV32MachineDef",
    "RISCV64MachineDef",
    "TriCoreMachineDef",
    "X86RealModeMachineDef",
    "UnicornMachineDef",
]
