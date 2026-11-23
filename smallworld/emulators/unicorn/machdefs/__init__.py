from .aarch64 import (
    AArch64BEMachineDef,
    AArch64MachineDef,
    AArch64V85ABEMachineDef,
    AArch64V85AMachineDef,
)
from .amd64 import AMD64MachineDef
from .arm import (
    ARMv4BEMachineDef,
    ARMv4MachineDef,
    ARMv4TBEMachineDef,
    ARMv4TMachineDef,
    ARMv5TBEMachineDef,
    ARMv5TMachineDef,
    ARMv6MMachineDef,
    ARMv7AMachineDef,
    ARMv7EMMachineDef,
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
    "AArch64BEMachineDef",
    "AArch64V85AMachineDef",
    "AArch64V85ABEMachineDef",
    "AMD64MachineDef",
    "ARMv4MachineDef",
    "ARMv4TMachineDef",
    "ARMv5TMachineDef",
    "ARMv4BEMachineDef",
    "ARMv4TBEMachineDef",
    "ARMv5TBEMachineDef",
    "ARMv6MMachineDef",
    "ARMv7AMachineDef",
    "ARMv7EMMachineDef",
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
