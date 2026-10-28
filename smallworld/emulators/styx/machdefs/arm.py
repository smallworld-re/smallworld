"""Styx machine definitions for 32-bit ARM, except ARMv7-A (see ``armv7a``).

SmallWorld's soft-float A-profile ARM tests use two architectures:
  * ``ARM_V5T`` (``armv5t``) for the raw-binary scenarios (square/branch/...).
  * ``ARM_V6K`` (``armv6k``) for those and the ELF/hooking/model scenarios.

Both run ARM32 code, so both map to Styx's CycloneV (Cortex-A9, supports
ARM+Thumb). Styx has no ARMv5 or ARM11 target; the Cortex-A9 accepts a
superset of their instructions. ``ARM_V4`` and ``ARM_V4T`` map there too. ``ARM_V6M`` and ``ARM_V7M`` map to Kinetis21
(Cortex-M4F), the closest Styx target to a Cortex-M0 or M3. The user-visible
ARM register file matches between the two. ``ARM_V7EM`` is the Cortex-M4F
itself, FPU registers included.
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


class StyxARMv4MachineDef(StyxMachineDef):
    arch = Architecture.ARM_V4
    byteorder = Byteorder.LITTLE
    # Styx has no ARMv4 target; the Cortex-A9 accepts a superset.
    target = Target.CycloneV
    backend = Backend.Unicorn
    address_size = 4
    pc_register = "pc"
    lr_register = "lr"
    _registers = dict(_BASE_REGS)


class StyxARMv4TMachineDef(StyxMachineDef):
    arch = Architecture.ARM_V4T
    byteorder = Byteorder.LITTLE
    # Styx has no ARMv4T target; the Cortex-A9 accepts a superset.
    target = Target.CycloneV
    backend = Backend.Unicorn
    address_size = 4
    pc_register = "pc"
    lr_register = "lr"
    _registers = dict(_BASE_REGS)


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


class StyxARMv7EMMachineDef(StyxMachineDef):
    arch = Architecture.ARM_V7EM
    byteorder = Byteorder.LITTLE
    # Kinetis21 is a Cortex-M4F: ARMv7E-M with FPv4-SP.
    target = Target.Kinetis21
    backend = Backend.Unicorn
    address_size = 4
    pc_register = "pc"
    lr_register = "lr"
    _registers = {
        **_BASE_REGS,
        "fpscr": ArmRegister.Fpscr,
        **{f"s{i}": getattr(ArmRegister, f"S{i}") for i in range(32)},
        **{f"d{i}": getattr(ArmRegister, f"D{i}") for i in range(16)},
    }


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
