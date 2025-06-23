import typing

import capstone

from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef

# PowerPC's register naming convention is extrmely annoying:
# it doesn't have one.
#
# Both the general-purpose registers
# and floating-point registers are solely referenced by number,
# thus making it maddening to tell which one you're talking about.
#
# Also, registers do have special uses within the ABI,
# but aside from sp and bp, they're not really written down.


class PowerPCPlatformDef(PlatformDef):
    byteorder = Byteorder.BIG

    capstone_arch = capstone.CS_ARCH_PPC

    # Special registers
    # - r0 and r2 are reserved for the assembler.
    # - r1 is the stack pointer
    # - r31 is the base (frame) pointer
    general_purpose_registers = [f"r{i}" for i in range(3, 31)]

    @property
    def registers(self) -> typing.Dict[str, RegisterDef]:
        return self._registers

    def __init__(self):
        self._registers = {
            # *** General Purpose Registers ***
            # NOTE: Used expressive names for GPRs and FPRs.
            # gasm just refers to GPRs and FPRS by number.
            # They use the same numbers; it's very annoying.
            "r0": RegisterDef(name="r0", size=self.address_size),
            # NOTE: GPR 1 is also the stack pointer.
            "r1": RegisterDef(name="r1", size=self.address_size),
            "sp": RegisterAliasDef("sp", parent="r1", size=self.address_size, offset=0),
            "r2": RegisterDef(name="r2", size=self.address_size),
            "r3": RegisterDef(name="r3", size=self.address_size),
            "r4": RegisterDef(name="r4", size=self.address_size),
            "r5": RegisterDef(name="r5", size=self.address_size),
            "r6": RegisterDef(name="r6", size=self.address_size),
            "r7": RegisterDef(name="r7", size=self.address_size),
            "r8": RegisterDef(name="r8", size=self.address_size),
            "r9": RegisterDef(name="r9", size=self.address_size),
            "r10": RegisterDef(name="r10", size=self.address_size),
            "r11": RegisterDef(name="r11", size=self.address_size),
            "r12": RegisterDef(name="r12", size=self.address_size),
            "r13": RegisterDef(name="r13", size=self.address_size),
            "r14": RegisterDef(name="r14", size=self.address_size),
            "r15": RegisterDef(name="r15", size=self.address_size),
            "r16": RegisterDef(name="r16", size=self.address_size),
            "r17": RegisterDef(name="r17", size=self.address_size),
            "r18": RegisterDef(name="r18", size=self.address_size),
            "r19": RegisterDef(name="r19", size=self.address_size),
            "r20": RegisterDef(name="r20", size=self.address_size),
            "r21": RegisterDef(name="r21", size=self.address_size),
            "r22": RegisterDef(name="r22", size=self.address_size),
            "r23": RegisterDef(name="r23", size=self.address_size),
            "r24": RegisterDef(name="r24", size=self.address_size),
            "r25": RegisterDef(name="r25", size=self.address_size),
            "r26": RegisterDef(name="r26", size=self.address_size),
            "r27": RegisterDef(name="r27", size=self.address_size),
            "r28": RegisterDef(name="r28", size=self.address_size),
            "r29": RegisterDef(name="r29", size=self.address_size),
            "r30": RegisterDef(name="r30", size=self.address_size),
            # NOTE: GPR 31 is also the base pointer
            "r31": RegisterDef(name="r31", size=self.address_size),
            "bp": RegisterAliasDef(
                name="bp", parent="r31", size=self.address_size, offset=0
            ),
            # Floating Point Registers
            # Always 8 bytes, regardless of self.address_size.
            "f0": RegisterDef(name="f0", size=8),
            "f1": RegisterDef(name="f1", size=8),
            "f2": RegisterDef(name="f2", size=8),
            "f3": RegisterDef(name="f3", size=8),
            "f4": RegisterDef(name="f4", size=8),
            "f5": RegisterDef(name="f5", size=8),
            "f6": RegisterDef(name="f6", size=8),
            "f7": RegisterDef(name="f7", size=8),
            "f8": RegisterDef(name="f8", size=8),
            "f9": RegisterDef(name="f9", size=8),
            "f10": RegisterDef(name="f10", size=8),
            "f11": RegisterDef(name="f11", size=8),
            "f12": RegisterDef(name="f12", size=8),
            "f13": RegisterDef(name="f13", size=8),
            "f14": RegisterDef(name="f14", size=8),
            "f15": RegisterDef(name="f15", size=8),
            "f16": RegisterDef(name="f16", size=8),
            "f17": RegisterDef(name="f17", size=8),
            "f18": RegisterDef(name="f18", size=8),
            "f19": RegisterDef(name="f19", size=8),
            "f20": RegisterDef(name="f20", size=8),
            "f21": RegisterDef(name="f21", size=8),
            "f22": RegisterDef(name="f22", size=8),
            "f23": RegisterDef(name="f23", size=8),
            "f24": RegisterDef(name="f24", size=8),
            "f25": RegisterDef(name="f25", size=8),
            "f26": RegisterDef(name="f26", size=8),
            "f27": RegisterDef(name="f27", size=8),
            "f28": RegisterDef(name="f28", size=8),
            "f29": RegisterDef(name="f29", size=8),
            "f30": RegisterDef(name="f30", size=8),
            "f31": RegisterDef(name="f31", size=8),
            # *** Pointer Registers ***
            # Program Counter.
            # Not really a register; nothing can access it directly
            "pc": RegisterDef(name="pc", size=self.address_size),
            # Link Register
            "lr": RegisterDef(name="lr", size=self.address_size),
            # Counter Register
            # Acts either as a loop index, or a branch target register
            # Only `ctr` and `lr` can act as branch targets.
            "ctr": RegisterDef(name="ctr", size=self.address_size),
            # *** Condition Registers ***
            # The actual condition register `cr` is a single 32-bit register,
            # but it's broken into eight 4-bit fields which are accessed separately.
            #
            # Certain operations use specific registers by default,
            # but some tests can specify a destination register.
            "cr0": RegisterDef(name="cr0", size=1),  # Integer condition bits
            "cr1": RegisterDef(name="cr1", size=1),  # Floating point condition bits
            "cr2": RegisterDef(name="cr2", size=1),
            "cr3": RegisterDef(name="cr3", size=1),
            "cr4": RegisterDef(name="cr4", size=1),
            "cr5": RegisterDef(name="cr5", size=1),
            "cr6": RegisterDef(name="cr6", size=1),
            "cr7": RegisterDef(name="cr7", size=1),
            # Integer Exception Register
            "xer": RegisterDef(name="xer", size=4),
            # Floating Point Status and Control Register
            "fpscr": RegisterDef(name="fpscr", size=4),
            # TODO: This only focuses on the user-facing registrers.
            # ppc has a huge number of privileged registers.
            # Extend this as needed.
        }


class PowerPC32(PowerPCPlatformDef):
    architecture = Architecture.POWERPC32

    address_size = 4
    capstone_mode = capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN


class PowerPC64(PowerPCPlatformDef):
    architecture = Architecture.POWERPC64

    address_size = 8
    capstone_mode = capstone.CS_MODE_64 | capstone.CS_MODE_BIG_ENDIAN
