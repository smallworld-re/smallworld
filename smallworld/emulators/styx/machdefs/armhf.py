"""Styx machine definition for hard-float ARM (`Architecture.ARM_V7A`).

Styx exposes a 32-bit Cortex-A9 firmware target (`CycloneV`) which supports
both ARM and Thumb modes, matching armhf semantics. Cortex-M targets like
Kinetis21 only support Thumb-2 and would fail to decode ARM32 instructions
that armhf test binaries use, so we route armhf through CycloneV.
"""

from styx_emulator.arch.arm import ArmRegister
from styx_emulator.cpu import Backend
from styx_emulator.processor import Target

from ....platforms import Architecture, Byteorder
from .machdef import StyxMachineDef


class StyxARMv7AMachineDef(StyxMachineDef):
    arch = Architecture.ARM_V7A
    byteorder = Byteorder.LITTLE
    target = Target.CycloneV
    backend = Backend.Unicorn
    address_size = 4
    pc_register = "pc"
    lr_register = "lr"

    _registers = {
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
        "fpscr": ArmRegister.Fpscr,
        "fpexc": ArmRegister.Fpexc,
        "fpsid": ArmRegister.Fpsid,
    }
    # Floating-point registers (s/d/q) — populated below so we can build the
    # name list programmatically without exploding the literal.
    for _i in range(32):
        _registers[f"s{_i}"] = getattr(ArmRegister, f"S{_i}")
        if _i < 32:
            _registers[f"d{_i}"] = getattr(ArmRegister, f"D{_i}")
        if _i < 16:
            _registers[f"q{_i}"] = getattr(ArmRegister, f"Q{_i}")
    del _i
