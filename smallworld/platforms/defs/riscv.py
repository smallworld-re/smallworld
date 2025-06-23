import capstone

from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef


class RiscV64(PlatformDef):
    architecture = Architecture.RISCV64
    byteorder = Byteorder.LITTLE

    address_size = 8

    capstone_arch = capstone.CS_ARCH_RISCV
    capstone_mode = capstone.CS_MODE_RISCV64

    pc_register = "pc"

    # Special registers:
    # - x0 is wired to zero
    # - x1 is the link register
    # - x2 is the stack pointer
    # - x3 is the global pointer
    # - x4 is the thread pointer
    general_purpose_registers = [f"x{i}" for i in range(0, 32)]

    registers = {
        # *** General-Purpose Registers ***
        # x0 is wired to 0, and aliased as "zero"
        "x0": RegisterDef(name="x0", size=8),
        "zero": RegisterAliasDef(name="zero", parent="x0", size=8, offset=0),
        # x1 acts as the link register
        # NOTE: ra is the official name; lr might be an angr invention.
        "x1": RegisterDef(name="x1", size=8),
        "ra": RegisterAliasDef(name="ra", parent="x1", size=8, offset=0),
        # x2 acts as the stack pointer
        "x2": RegisterDef(name="x2", size=8),
        "sp": RegisterAliasDef(name="sp", parent="x2", size=8, offset=0),
        # x3 acts as the global pointer
        "x3": RegisterDef(name="x3", size=8),
        "gp": RegisterAliasDef(name="gp", parent="x3", size=8, offset=0),
        # x4 acts as the thread pointer
        "x4": RegisterDef(name="x4", size=8),
        "tp": RegisterAliasDef(name="tp", parent="x4", size=8, offset=0),
        # x5 is a temporary register
        "x5": RegisterDef(name="x5", size=8),
        "t0": RegisterAliasDef(name="t0", parent="x5", size=8, offset=0),
        # x6 is a temporary register
        "x6": RegisterDef(name="x6", size=8),
        "t1": RegisterAliasDef(name="t1", parent="x6", size=8, offset=0),
        # x7 is a temporary register
        "x7": RegisterDef(name="x7", size=8),
        "t2": RegisterAliasDef(name="t2", parent="x7", size=8, offset=0),
        # x8 is a callee-saved register
        "x8": RegisterDef(name="x8", size=8),
        "s0": RegisterAliasDef(name="s0", parent="x8", size=8, offset=0),
        # x9 is a callee-saved register
        "x9": RegisterDef(name="x9", size=8),
        "s1": RegisterAliasDef(name="s1", parent="x9", size=8, offset=0),
        # x10 is argument 0
        "x10": RegisterDef(name="x10", size=8),
        "a0": RegisterAliasDef(name="a0", parent="x10", size=8, offset=0),
        # x11 is argument 1
        "x11": RegisterDef(name="x11", size=8),
        "a1": RegisterAliasDef(name="a1", parent="x11", size=8, offset=0),
        # x12 is argument 2
        "x12": RegisterDef(name="x12", size=8),
        "a2": RegisterAliasDef(name="a2", parent="x12", size=8, offset=0),
        # x13 is argument 3
        "x13": RegisterDef(name="x13", size=8),
        "a3": RegisterAliasDef(name="a3", parent="x13", size=8, offset=0),
        # x14 is argument 4
        "x14": RegisterDef(name="x14", size=8),
        "a4": RegisterAliasDef(name="a4", parent="x14", size=8, offset=0),
        # x15 is argument 5
        "x15": RegisterDef(name="x15", size=8),
        "a5": RegisterAliasDef(name="a5", parent="x15", size=8, offset=0),
        # x16 is argument 6
        "x16": RegisterDef(name="x16", size=8),
        "a6": RegisterAliasDef(name="a6", parent="x16", size=8, offset=0),
        # x17 is argument 7
        "x17": RegisterDef(name="x17", size=8),
        "a7": RegisterAliasDef(name="a7", parent="x17", size=8, offset=0),
        # x18 is a callee-saved register
        "x18": RegisterDef(name="x18", size=8),
        "s2": RegisterAliasDef(name="s2", parent="x18", size=8, offset=0),
        # x19 is a callee-saved register
        "x19": RegisterDef(name="x19", size=8),
        "s3": RegisterAliasDef(name="s3", parent="x19", size=8, offset=0),
        # x20 is a callee-saved register
        "x20": RegisterDef(name="x20", size=8),
        "s4": RegisterAliasDef(name="s4", parent="x20", size=8, offset=0),
        # x21 is a callee-saved register
        "x21": RegisterDef(name="x21", size=8),
        "s5": RegisterAliasDef(name="s5", parent="x21", size=8, offset=0),
        # x22 is a callee-saved register
        "x22": RegisterDef(name="x22", size=8),
        "s6": RegisterAliasDef(name="s6", parent="x22", size=8, offset=0),
        # x23 is a callee-saved register
        "x23": RegisterDef(name="x23", size=8),
        "s7": RegisterAliasDef(name="s7", parent="x23", size=8, offset=0),
        # x24 is a callee-saved register
        "x24": RegisterDef(name="x24", size=8),
        "s8": RegisterAliasDef(name="s8", parent="x24", size=8, offset=0),
        # x25 is a callee-saved register
        "x25": RegisterDef(name="x25", size=8),
        "s9": RegisterAliasDef(name="s9", parent="x25", size=8, offset=0),
        # x26 is a callee-saved register
        "x26": RegisterDef(name="x26", size=8),
        "s10": RegisterAliasDef(name="s10", parent="x26", size=8, offset=0),
        # x27 is a callee-saved register
        "x27": RegisterDef(name="x27", size=8),
        "s11": RegisterAliasDef(name="s11", parent="x27", size=8, offset=0),
        # x28 is a temporary register
        "x28": RegisterDef(name="x28", size=8),
        "t3": RegisterAliasDef(name="t3", parent="x28", size=8, offset=0),
        # x29 is a temporary register
        "x29": RegisterDef(name="x29", size=8),
        "t4": RegisterAliasDef(name="t4", parent="x29", size=8, offset=0),
        # x30 is a temporary register
        "x30": RegisterDef(name="x30", size=8),
        "t5": RegisterAliasDef(name="t5", parent="x30", size=8, offset=0),
        # x31 is a temporary register
        "x31": RegisterDef(name="x31", size=8),
        "t6": RegisterAliasDef(name="t6", parent="x31", size=8, offset=0),
        # *** Program Counter ***
        "pc": RegisterDef(name="pc", size=8),
        # *** Floating-Point Registers ***
        # f0 is a temporary register
        "f0": RegisterDef(name="f0", size=8),
        "ft0": RegisterAliasDef(name="ft0", parent="f0", size=8, offset=0),
        # f1 is a temporary register
        "f1": RegisterDef(name="f1", size=8),
        "ft1": RegisterAliasDef(name="ft1", parent="f1", size=8, offset=0),
        # f2 is a temporary register
        "f2": RegisterDef(name="f2", size=8),
        "ft2": RegisterAliasDef(name="ft2", parent="f2", size=8, offset=0),
        # f3 is a temporary register
        "f3": RegisterDef(name="f3", size=8),
        "ft3": RegisterAliasDef(name="ft3", parent="f3", size=8, offset=0),
        # f4 is a temporary register
        "f4": RegisterDef(name="f4", size=8),
        "ft4": RegisterAliasDef(name="ft4", parent="f4", size=8, offset=0),
        # f5 is a temporary register
        "f5": RegisterDef(name="f5", size=8),
        "ft5": RegisterAliasDef(name="ft5", parent="f5", size=8, offset=0),
        # f6 is a temporary register
        "f6": RegisterDef(name="f6", size=8),
        "ft6": RegisterAliasDef(name="ft6", parent="f6", size=8, offset=0),
        # f7 is a temporary register
        "f7": RegisterDef(name="f7", size=8),
        "ft7": RegisterAliasDef(name="ft7", parent="f7", size=8, offset=0),
        # f8 is a callee saved register
        "f8": RegisterDef(name="f8", size=8),
        "fs0": RegisterAliasDef(name="fs0", parent="f8", size=8, offset=0),
        # f9 is a callee saved register
        "f9": RegisterDef(name="f9", size=8),
        "fs1": RegisterAliasDef(name="fs1", parent="f9", size=8, offset=0),
        # f10 is argument 0
        "f10": RegisterDef(name="f10", size=8),
        "fa0": RegisterAliasDef(name="fa0", parent="f10", size=8, offset=0),
        # f11 is argument 1
        "f11": RegisterDef(name="f11", size=8),
        "fa1": RegisterAliasDef(name="fa1", parent="f11", size=8, offset=0),
        # f12 is argument 2
        "f12": RegisterDef(name="f12", size=8),
        "fa2": RegisterAliasDef(name="fa2", parent="f12", size=8, offset=0),
        # f13 is argument 3
        "f13": RegisterDef(name="f13", size=8),
        "fa3": RegisterAliasDef(name="fa3", parent="f13", size=8, offset=0),
        # f14 is argument 4
        "f14": RegisterDef(name="f14", size=8),
        "fa4": RegisterAliasDef(name="fa4", parent="f14", size=8, offset=0),
        # f15 is argument 5
        "f15": RegisterDef(name="f15", size=8),
        "fa5": RegisterAliasDef(name="fa5", parent="f15", size=8, offset=0),
        # f16 is argument 6
        "f16": RegisterDef(name="f16", size=8),
        "fa6": RegisterAliasDef(name="fa6", parent="f16", size=8, offset=0),
        # f7 is argument 7
        "f17": RegisterDef(name="f17", size=8),
        "fa7": RegisterAliasDef(name="fa7", parent="f17", size=8, offset=0),
        # f18 is a callee-saved register
        "f18": RegisterDef(name="f18", size=8),
        "fs2": RegisterAliasDef(name="fs2", parent="f18", size=8, offset=0),
        # f19 is a callee-saved register
        "f19": RegisterDef(name="f19", size=8),
        "fs3": RegisterAliasDef(name="fs3", parent="f19", size=8, offset=0),
        # f20 is a callee-saved register
        "f20": RegisterDef(name="f20", size=8),
        "fs4": RegisterAliasDef(name="fs4", parent="f20", size=8, offset=0),
        # f21 is a callee-saved register
        "f21": RegisterDef(name="f21", size=8),
        "fs5": RegisterAliasDef(name="fs5", parent="f21", size=8, offset=0),
        # f22 is a callee-saved register
        "f22": RegisterDef(name="f22", size=8),
        "fs6": RegisterAliasDef(name="fs6", parent="f22", size=8, offset=0),
        # f23 is a callee-saved register
        "f23": RegisterDef(name="f23", size=8),
        "fs7": RegisterAliasDef(name="fs7", parent="f23", size=8, offset=0),
        # f24 is a callee-saved register
        "f24": RegisterDef(name="f24", size=8),
        "fs8": RegisterAliasDef(name="fs8", parent="f24", size=8, offset=0),
        # f25 is a callee-saved register
        "f25": RegisterDef(name="f25", size=8),
        "fs9": RegisterAliasDef(name="fs9", parent="f25", size=8, offset=0),
        # f26 is a callee-saved register
        "f26": RegisterDef(name="f26", size=8),
        "fs10": RegisterAliasDef(name="fs10", parent="f26", size=8, offset=0),
        # f27 is a callee-saved register
        "f27": RegisterDef(name="f27", size=8),
        "fs11": RegisterAliasDef(name="fs11", parent="f27", size=8, offset=0),
        # f28 is a temporary register
        "f28": RegisterDef(name="f28", size=8),
        "ft8": RegisterAliasDef(name="ft8", parent="f28", size=8, offset=0),
        # f29 is a temporary register
        "f29": RegisterDef(name="f29", size=8),
        "ft9": RegisterAliasDef(name="ft9", parent="f29", size=8, offset=0),
        # f30 is a temporary register
        "f30": RegisterDef(name="f30", size=8),
        "ft10": RegisterAliasDef(name="ft10", parent="f30", size=8, offset=0),
        # f31 is a temporary register
        "f31": RegisterDef(name="f31", size=8),
        "ft11": RegisterAliasDef(name="ft11", parent="f31", size=8, offset=0),
        # *** Vector Registers ***
        # NOTE: These exist, but are not supported
        # *** Control and Status Registers ***
        # NOTE: These exist, but aren't supported.
    }
