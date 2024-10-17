import archinfo

from ....arch import aarch64_arch
from ....platforms import Architecture, Byteorder
from .machdef import AngrMachineDef


class AArch64MachineDef(AngrMachineDef):
    arch = Architecture.AARCH64
    byteorder = Byteorder.LITTLE

    angr_arch = archinfo.arch_aarch64.ArchAArch64()
    pc_reg = "pc"

    _registers = {k: k for k in aarch64_arch.info}
    # Angr is very strictly user-space; it does not model most system registers
    _registers["elr_el1"] = ""
    _registers["elr_el2"] = ""
    _registers["elr_el3"] = ""
    _registers["esr_el1"] = ""
    _registers["esr_el2"] = ""
    _registers["esr_el3"] = ""
    _registers["far_el1"] = ""
    _registers["far_el2"] = ""
    _registers["far_el3"] = ""
    _registers["vbar_el0"] = ""
    _registers["vbar_el1"] = ""
    _registers["vbar_el2"] = ""
    _registers["vbar_el3"] = ""
    _registers["cpacr_el1"] = ""
    _registers["mair_el1"] = ""
    _registers["par_el1"] = ""
    _registers["ttbr0_el1"] = ""
    _registers["ttbr1_el1"] = ""
    _registers["tpidr_el0"] = ""
    _registers["tpidr_el1"] = ""
    _registers["tpidrro_el0"] = ""
