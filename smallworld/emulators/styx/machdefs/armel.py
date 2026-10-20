"""Styx machine definitions for 32-bit ARM ``armel`` variants.

SmallWorld's soft-float ARM tests use two architectures:
  * ``ARM_V5T`` (``armv5t``) for the raw-binary scenarios (square/branch/...).
  * ``ARM_V6K`` (``armv6k``) for the ELF/hooking/model scenarios.

Both run ARM32 code, so both map to Styx's CycloneV (Cortex-A9, supports
ARM+Thumb). Styx has no ARMv5 or ARM11 target; the Cortex-A9 accepts a
superset of their instructions. ``ARM_V6M`` and ``ARM_V7M`` map to Kinetis21
(Cortex-M4F), the closest Styx target to a Cortex-M0 or M3. The user-visible
ARM register file matches between the two.
"""

from styx_emulator.arch.arm import ArmRegister
from styx_emulator.cpu import Backend
from styx_emulator.processor import Target

from ....platforms import Architecture, Byteorder
from .machdef import StyxMachineDef

_BASE_REGS = {
    "r0": ArmRegister.R0,
    "r1": ArmRegister.R1,
    "r2": ArmRegister.R2,
    "r3": ArmRegister.R3,
    "r4": ArmRegister.R4,
    "r5": ArmRegister.R5,
    "r6": ArmRegister.R6,
    "r7": ArmRegister.R7,
    "r8": ArmRegister.R8,
    "r9": ArmRegister.R9,
    "sb": ArmRegister.Sb,
    "r10": ArmRegister.R10,
    "sl": ArmRegister.Sl,
    "r11": ArmRegister.R11,
    "fp": ArmRegister.Fp,
    "r12": ArmRegister.R12,
    "ip": ArmRegister.Ip,
    "r13": ArmRegister.R13,
    "sp": ArmRegister.Sp,
    "r14": ArmRegister.R14,
    "lr": ArmRegister.Lr,
    "r15": ArmRegister.R15,
    "pc": ArmRegister.Pc,
    "cpsr": ArmRegister.Cpsr,
    "apsr": ArmRegister.Apsr,
    "spsr": ArmRegister.Spsr,
}


class StyxARMv5TMachineDef(StyxMachineDef):
    arch = Architecture.ARM_V5T
    byteorder = Byteorder.LITTLE
    target = Target.CycloneV
    backend = Backend.Unicorn
    address_size = 4
    pc_register = "pc"
    lr_register = "lr"
    _registers = dict(_BASE_REGS)


class StyxARMv6KMachineDef(StyxMachineDef):
    arch = Architecture.ARM_V6K
    byteorder = Byteorder.LITTLE
    target = Target.CycloneV
    backend = Backend.Unicorn
    address_size = 4
    pc_register = "pc"
    lr_register = "lr"
    _registers = dict(_BASE_REGS)


class StyxARMv6MMachineDef(StyxMachineDef):
    arch = Architecture.ARM_V6M
    byteorder = Byteorder.LITTLE
    # Cortex-M0 is Thumb-only — Kinetis21 (Cortex-M4F) is the closest Styx
    # target supporting Thumb-2.
    target = Target.Kinetis21
    backend = Backend.Unicorn
    address_size = 4
    pc_register = "pc"
    lr_register = "lr"
    _registers = dict(_BASE_REGS)


class StyxARMv7MMachineDef(StyxMachineDef):
    arch = Architecture.ARM_V7M
    byteorder = Byteorder.LITTLE
    # Kinetis21 is a Cortex-M4F (ARMv7E-M), a superset of ARMv7-M.
    target = Target.Kinetis21
    backend = Backend.Unicorn
    address_size = 4
    pc_register = "pc"
    lr_register = "lr"
    _registers = dict(_BASE_REGS)
