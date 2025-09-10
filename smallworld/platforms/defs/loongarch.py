import typing

from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef


class LoongArchPlatformDef(PlatformDef):
    byteorder = Byteorder.LITTLE

    # NOTE: Capstone does not yet support LoongArch
    capstone_arch = -1
    capstone_mode = -1

    pc_register = "pc"
    sp_register = "r3"

    conditional_branch_mnemonics = {
        "beq",
        "bne",
        "blt",
        "bge",
        "bltu",
        "bgeu",
        "beqz",
    }
    # LoongArch follows MIPS' philosophy.
    # Integer comparisons are built into the conditional branch instructions.
    # I'd bet there are conditional FPU instructions,
    # if I can find them.
    compare_mnemonics = set()

    @property
    def general_purpose_registers(self) -> typing.List[str]:
        # Special registers:
        # r0: Hard-wired to zero
        # r1: Return address
        # r2: TLS pointer
        # r3: Stack pointer
        # r21: Per-CPU pointer
        return ["r{i}" for i in range(4, 32) if i != 21]

    @property
    def registers(self) -> typing.Dict[str, RegisterDef]:
        return self._registers

    def __init__(self):
        self._registers = {
            # Program counter (not a real register)
            "pc": RegisterDef(name="pc", size=self.address_size),
            # Zero register
            "r0": RegisterDef(name="r0", size=self.address_size),
            "zero": RegisterAliasDef(
                name="zero", parent="r0", size=self.address_size, offset=0
            ),
            # Return address
            "r1": RegisterDef(name="r1", size=self.address_size),
            "ra": RegisterAliasDef(
                name="ra", parent="r1", size=self.address_size, offset=0
            ),
            # TLS pointer
            "r2": RegisterDef(name="r2", size=self.address_size),
            "tp": RegisterAliasDef(
                name="tp", parent="r2", size=self.address_size, offset=0
            ),
            # Stack pointer
            "r3": RegisterDef(name="r3", size=self.address_size),
            "sp": RegisterAliasDef(
                name="sp", parent="r3", size=self.address_size, offset=0
            ),
            # Arguments.
            # a0 and a1 are also the return registers
            "r4": RegisterDef(name="r4", size=self.address_size),
            "a0": RegisterAliasDef(
                name="a0", parent="r4", size=self.address_size, offset=0
            ),
            "v0": RegisterAliasDef(
                name="v0", parent="r4", size=self.address_size, offset=0
            ),
            "r5": RegisterDef(name="r5", size=self.address_size),
            "a1": RegisterAliasDef(
                name="a1", parent="r5", size=self.address_size, offset=0
            ),
            "v1": RegisterAliasDef(
                name="v1", parent="r5", size=self.address_size, offset=0
            ),
            "r6": RegisterDef(name="r6", size=self.address_size),
            "a2": RegisterAliasDef(
                name="a2", parent="r6", size=self.address_size, offset=0
            ),
            "r7": RegisterDef(name="r7", size=self.address_size),
            "a3": RegisterAliasDef(
                name="a3", parent="r7", size=self.address_size, offset=0
            ),
            "r8": RegisterDef(name="r8", size=self.address_size),
            "a4": RegisterAliasDef(
                name="a4", parent="r8", size=self.address_size, offset=0
            ),
            "r9": RegisterDef(name="r9", size=self.address_size),
            "a5": RegisterAliasDef(
                name="a5", parent="r9", size=self.address_size, offset=0
            ),
            "r10": RegisterDef(name="r10", size=self.address_size),
            "a6": RegisterAliasDef(
                name="a6", parent="r10", size=self.address_size, offset=0
            ),
            "r11": RegisterDef(name="r11", size=self.address_size),
            "a7": RegisterAliasDef(
                name="a7", parent="r11", size=self.address_size, offset=0
            ),
            # Temporary registers
            "r12": RegisterDef(name="r12", size=self.address_size),
            "t0": RegisterAliasDef(
                name="t0", parent="r12", size=self.address_size, offset=0
            ),
            "r13": RegisterDef(name="r13", size=self.address_size),
            "t1": RegisterAliasDef(
                name="t1", parent="r13", size=self.address_size, offset=0
            ),
            "r14": RegisterDef(name="r14", size=self.address_size),
            "t2": RegisterAliasDef(
                name="t2", parent="r14", size=self.address_size, offset=0
            ),
            "r15": RegisterDef(name="r15", size=self.address_size),
            "t3": RegisterAliasDef(
                name="t3", parent="r15", size=self.address_size, offset=0
            ),
            "r16": RegisterDef(name="r16", size=self.address_size),
            "t4": RegisterAliasDef(
                name="t4", parent="r16", size=self.address_size, offset=0
            ),
            "r17": RegisterDef(name="r17", size=self.address_size),
            "t5": RegisterAliasDef(
                name="t5", parent="r17", size=self.address_size, offset=0
            ),
            "r18": RegisterDef(name="r18", size=self.address_size),
            "t6": RegisterAliasDef(
                name="t6", parent="r18", size=self.address_size, offset=0
            ),
            "r19": RegisterDef(name="r19", size=self.address_size),
            "t7": RegisterAliasDef(
                name="t7", parent="r19", size=self.address_size, offset=0
            ),
            "r20": RegisterDef(name="r20", size=self.address_size),
            "t8": RegisterAliasDef(
                name="t8", parent="r20", size=self.address_size, offset=0
            ),
            # Per-CPU Base Address
            "r21": RegisterDef(name="r21", size=self.address_size),
            "u0": RegisterAliasDef(
                name="u0", parent="r21", size=self.address_size, offset=0
            ),
            # Frame Pointer
            "r22": RegisterDef(name="r22", size=self.address_size),
            "fp": RegisterAliasDef(
                name="fp", parent="r22", size=self.address_size, offset=0
            ),
            # Static registers
            "r23": RegisterDef(name="r23", size=self.address_size),
            "s0": RegisterAliasDef(
                name="s0", parent="r23", size=self.address_size, offset=0
            ),
            "r24": RegisterDef(name="r24", size=self.address_size),
            "s1": RegisterAliasDef(
                name="s1", parent="r24", size=self.address_size, offset=0
            ),
            "r25": RegisterDef(name="r25", size=self.address_size),
            "s2": RegisterAliasDef(
                name="s2", parent="r25", size=self.address_size, offset=0
            ),
            "r26": RegisterDef(name="r26", size=self.address_size),
            "s3": RegisterAliasDef(
                name="s3", parent="r26", size=self.address_size, offset=0
            ),
            "r27": RegisterDef(name="r27", size=self.address_size),
            "s4": RegisterAliasDef(
                name="s4", parent="r27", size=self.address_size, offset=0
            ),
            "r28": RegisterDef(name="r28", size=self.address_size),
            "s5": RegisterAliasDef(
                name="s5", parent="r28", size=self.address_size, offset=0
            ),
            "r29": RegisterDef(name="r29", size=self.address_size),
            "s6": RegisterAliasDef(
                name="s6", parent="r29", size=self.address_size, offset=0
            ),
            "r30": RegisterDef(name="r30", size=self.address_size),
            "s7": RegisterAliasDef(
                name="s7", parent="r30", size=self.address_size, offset=0
            ),
            "r31": RegisterDef(name="r31", size=self.address_size),
            "s8": RegisterAliasDef(
                name="s8", parent="r31", size=self.address_size, offset=0
            ),
            # Floating-point arguments.
            # fa0 and fa1 are also return values
            "f0": RegisterDef(name="f0", size=8),
            "fa0": RegisterAliasDef(name="fa0", parent="f0", size=8, offset=0),
            "f1": RegisterDef(name="f1", size=8),
            "fa1": RegisterAliasDef(name="fa1", parent="f1", size=8, offset=0),
            "f2": RegisterDef(name="f2", size=8),
            "fa2": RegisterAliasDef(name="fa2", parent="f2", size=8, offset=0),
            "f3": RegisterDef(name="f3", size=8),
            "fa3": RegisterAliasDef(name="fa3", parent="f3", size=8, offset=0),
            "f4": RegisterDef(name="f4", size=8),
            "fa4": RegisterAliasDef(name="fa4", parent="f4", size=8, offset=0),
            "f5": RegisterDef(name="f5", size=8),
            "fa5": RegisterAliasDef(name="fa5", parent="f5", size=8, offset=0),
            "f6": RegisterDef(name="f6", size=8),
            "fa6": RegisterAliasDef(name="fa6", parent="f6", size=8, offset=0),
            "f7": RegisterDef(name="f7", size=8),
            "fa7": RegisterAliasDef(name="fa7", parent="f7", size=8, offset=0),
            # Floating-point temporary registers
            "f8": RegisterDef(name="f8", size=8),
            "ft0": RegisterAliasDef(name="ft0", parent="f8", size=8, offset=0),
            "f9": RegisterDef(name="f9", size=8),
            "ft1": RegisterAliasDef(name="ft1", parent="f9", size=8, offset=0),
            "f10": RegisterDef(name="f10", size=8),
            "ft2": RegisterAliasDef(name="ft2", parent="f10", size=8, offset=0),
            "f11": RegisterDef(name="f11", size=8),
            "ft3": RegisterAliasDef(name="ft3", parent="f11", size=8, offset=0),
            "f12": RegisterDef(name="f12", size=8),
            "ft4": RegisterAliasDef(name="ft4", parent="f12", size=8, offset=0),
            "f13": RegisterDef(name="f13", size=8),
            "ft5": RegisterAliasDef(name="ft5", parent="f13", size=8, offset=0),
            "f14": RegisterDef(name="f14", size=8),
            "ft6": RegisterAliasDef(name="ft6", parent="f14", size=8, offset=0),
            "f15": RegisterDef(name="f15", size=8),
            "ft7": RegisterAliasDef(name="ft7", parent="f15", size=8, offset=0),
            "f16": RegisterDef(name="f16", size=8),
            "ft8": RegisterAliasDef(name="ft8", parent="f16", size=8, offset=0),
            "f17": RegisterDef(name="f17", size=8),
            "ft9": RegisterAliasDef(name="ft9", parent="f17", size=8, offset=0),
            "f18": RegisterDef(name="f18", size=8),
            "ft10": RegisterAliasDef(name="ft10", parent="f18", size=8, offset=0),
            "f19": RegisterDef(name="f19", size=8),
            "ft11": RegisterAliasDef(name="ft11", parent="f19", size=8, offset=0),
            "f20": RegisterDef(name="f20", size=8),
            "ft12": RegisterAliasDef(name="ft12", parent="f20", size=8, offset=0),
            "f21": RegisterDef(name="f21", size=8),
            "ft13": RegisterAliasDef(name="ft13", parent="f21", size=8, offset=0),
            "f22": RegisterDef(name="f22", size=8),
            "ft14": RegisterAliasDef(name="ft14", parent="f22", size=8, offset=0),
            "f23": RegisterDef(name="f23", size=8),
            "ft15": RegisterAliasDef(name="ft15", parent="f23", size=8, offset=0),
            # Floating-point static registers
            "f24": RegisterDef(name="f24", size=8),
            "fs0": RegisterAliasDef(name="fs0", parent="f24", size=8, offset=0),
            "f25": RegisterDef(name="f25", size=8),
            "fs1": RegisterAliasDef(name="fs1", parent="f25", size=8, offset=0),
            "f26": RegisterDef(name="f26", size=8),
            "fs2": RegisterAliasDef(name="fs2", parent="f26", size=8, offset=0),
            "f27": RegisterDef(name="f27", size=8),
            "fs3": RegisterAliasDef(name="fs3", parent="f27", size=8, offset=0),
            "f28": RegisterDef(name="f28", size=8),
            "fs4": RegisterAliasDef(name="fs4", parent="f28", size=8, offset=0),
            "f29": RegisterDef(name="f29", size=8),
            "fs5": RegisterAliasDef(name="fs5", parent="f29", size=8, offset=0),
            "f30": RegisterDef(name="f30", size=8),
            "fs6": RegisterAliasDef(name="fs6", parent="f30", size=8, offset=0),
            "f31": RegisterDef(name="f31", size=8),
            "fs7": RegisterAliasDef(name="fs7", parent="f31", size=8, offset=0),
        }


class LoongArch64(LoongArchPlatformDef):
    architecture = Architecture.LOONGARCH64
    address_size = 8


__all__ = ["LoongArch64"]
