import unicorn

from ....platforms import Architecture, Byteorder
from .machdef import UnicornMachineDef


class M68KMachineDef(UnicornMachineDef):
    arch = Architecture.M68K
    byteorder = Byteorder.BIG

    uc_arch = unicorn.UC_ARCH_M68K
    uc_mode = unicorn.UC_MODE_BIG_ENDIAN

    _registers = {
        # Data registers
        "d0": unicorn.m68k_const.UC_M68K_REG_D0,
        "d1": unicorn.m68k_const.UC_M68K_REG_D1,
        "d2": unicorn.m68k_const.UC_M68K_REG_D2,
        "d3": unicorn.m68k_const.UC_M68K_REG_D3,
        "d4": unicorn.m68k_const.UC_M68K_REG_D4,
        "d5": unicorn.m68k_const.UC_M68K_REG_D5,
        "d6": unicorn.m68k_const.UC_M68K_REG_D6,
        "d7": unicorn.m68k_const.UC_M68K_REG_D7,
        # Address registers
        "a0": unicorn.m68k_const.UC_M68K_REG_A0,
        "a1": unicorn.m68k_const.UC_M68K_REG_A1,
        "a2": unicorn.m68k_const.UC_M68K_REG_A2,
        "a3": unicorn.m68k_const.UC_M68K_REG_A3,
        "a4": unicorn.m68k_const.UC_M68K_REG_A4,
        "a5": unicorn.m68k_const.UC_M68K_REG_A5,
        "a6": unicorn.m68k_const.UC_M68K_REG_A6,
        # User stack pointer
        "usp": unicorn.m68k_const.UC_M68K_REG_A7,
        "sp": unicorn.m68k_const.UC_M68K_REG_A7,
        "a7": unicorn.m68k_const.UC_M68K_REG_A7,
        # Program counter
        "pc": unicorn.m68k_const.UC_M68K_REG_PC,
        # Floating-point control register
        "fpcr": unicorn.m68k_const.UC_M68K_REG_INVALID,
        # Floating-point status register
        "fpsr": unicorn.m68k_const.UC_M68K_REG_INVALID,
        # Floating-point instruction address register
        "fpiar": unicorn.m68k_const.UC_M68K_REG_INVALID,
        # Floating-point registers
        "fp0": unicorn.m68k_const.UC_M68K_REG_INVALID,
        "fp1": unicorn.m68k_const.UC_M68K_REG_INVALID,
        "fp2": unicorn.m68k_const.UC_M68K_REG_INVALID,
        "fp3": unicorn.m68k_const.UC_M68K_REG_INVALID,
        "fp4": unicorn.m68k_const.UC_M68K_REG_INVALID,
        "fp5": unicorn.m68k_const.UC_M68K_REG_INVALID,
        "fp6": unicorn.m68k_const.UC_M68K_REG_INVALID,
        "fp7": unicorn.m68k_const.UC_M68K_REG_INVALID,
        # NOTE: Everything past this point is privileged state
        "isp": unicorn.m68k_const.UC_M68K_REG_CR_ISP,
        "ssp": unicorn.m68k_const.UC_M68K_REG_CR_ISP,
        "msp": unicorn.m68k_const.UC_M68K_REG_CR_MSP,
        "sr": unicorn.m68k_const.UC_M68K_REG_SR,
        "ccr": unicorn.m68k_const.UC_M68K_REG_SR,
        # NOTE: vbr access is deprecated in Unicorn
        "vbr": unicorn.m68k_const.UC_M68K_REG_INVALID,
        "sfc": unicorn.m68k_const.UC_M68K_REG_CR_SFC,
        "dfc": unicorn.m68k_const.UC_M68K_REG_CR_DFC,
        "cacr": unicorn.m68k_const.UC_M68K_REG_CR_CACR,
        "urp": unicorn.m68k_const.UC_M68K_REG_CR_URP,
        "srp": unicorn.m68k_const.UC_M68K_REG_CR_SRP,
        "tc": unicorn.m68k_const.UC_M68K_REG_CR_TC,
        "dtt0": unicorn.m68k_const.UC_M68K_REG_CR_DTT0,
        "dtt1": unicorn.m68k_const.UC_M68K_REG_CR_DTT1,
        "itt0": unicorn.m68k_const.UC_M68K_REG_CR_ITT0,
        "itt1": unicorn.m68k_const.UC_M68K_REG_CR_ITT1,
        "mmusr": unicorn.m68k_const.UC_M68K_REG_CR_MMUSR,
    }
