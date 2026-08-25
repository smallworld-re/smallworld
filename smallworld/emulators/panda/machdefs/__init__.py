from .aarch64 import AArch64MachineDef
from .amd64 import AMD64MachineDef
from .arm import (  # ARMv6MMachineDef,; ARMv6MThumbMachineDef,
    ARMv5TMachineDef,
    ARMv7MMachineDef,
)
from .i386 import i386MachineDef
from .machdef import PandaMachineDef
from .mips import MIPSBEMachineDef, MIPSELMachineDef
from .mips64 import MIPS64BEMachineDef, MIPS64ELMachineDef
from .ppc import PowerPC32MachineDef  # , PowerPC64MachineDef
from .superh import SH2AFPUMachineDef
from .superh4 import SuperH4BEMachineDef, SuperH4ELMachineDef
from .tricore import TriCoreMachineDef

__all__ = [
    "AArch64MachineDef",
    "AMD64MachineDef",
    "PandaMachineDef",
    "ARMv5TMachineDef",
    #    "ARMv6MMachineDef",
    #    "ARMv6MThumbMachineDef",
    "ARMv7MMachineDef",
    "i386MachineDef",
    "MIPSBEMachineDef",
    "MIPSELMachineDef",
    "MIPS64BEMachineDef",
    "MIPS64ELMachineDef",
    "PowerPC32MachineDef",
    "SH2AFPUMachineDef",
    "SuperH4BEMachineDef",
    "SuperH4ELMachineDef",
    "TriCoreMachineDef",
    # "PowerPC64MachineDef",
]
