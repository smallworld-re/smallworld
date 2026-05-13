"""Styx machine definitions for 32-bit ARM ``armel`` variants.

SmallWorld's ``armel`` tests use two underlying architectures:
  * ``ARM_V5T`` for the raw-binary scenarios (square/branch/call/...) — these
    run ARM32 code that needs a Cortex-A class target.
  * ``ARM_V6M`` for the hooking/model scenarios — these run Thumb-only code
    that needs a Cortex-M class target.

We map them to Styx's CycloneV (Cortex-A9, supports ARM+Thumb) and Kinetis21
(Cortex-M4F, supports Thumb-2) respectively. The user-visible ARM register
file matches between the two.
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
