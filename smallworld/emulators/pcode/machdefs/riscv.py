from ....platforms import Architecture, Byteorder
from .machdef import PcodeMachineDef


class RISCV64MachineDef(PcodeMachineDef):
    arch = Architecture.RISCV64
    byteorder = Byteorder.LITTLE
    language_id = "RISCV:LE:64:default"

    pc_reg = "pc"
    address_size = 8

    _registers = {
        # *** General-Purpose Registers ***
        # x0 is wired to 0, and aliased as "zero"
        "x0": "zero",
        "zero": "zero",
        # x1 acts as the link register
        # NOTE:ra is the official name; lr might be an angr invention.
        "x1": "ra",
        "ra": "ra",
        # x2 acts as the stack pointer
        "x2": "sp",
        "sp": "sp",
        # x3 acts as the global pointer
        "x3": "gp",
        "gp": "gp",
        # x4 acts as the thread pointer
        "x4": "tp",
        "tp": "tp",
        # x5 is a temporary register
        "x5": "t0",
        "t0": "t0",
        # x6 is a temporary register
        "x6": "t1",
        "t1": "t1",
        # x7 is a temporary register
        "x7": "t2",
        "t2": "t2",
        # x8 is a callee-saved register
        "x8": "s0",
        "s0": "s0",
        # x9 is a callee-saved register
        "x9": "s1",
        "s1": "s1",
        # x10 is argument 0
        "x10": "a0",
        "a0": "a0",
        # x11 is argument 1
        "x11": "a1",
        "a1": "a1",
        # x12 is argument 2
        "x12": "a2",
        "a2": "a2",
        # x13 is argument 3
        "x13": "a3",
        "a3": "a3",
        # x14 is argument 4
        "x14": "a4",
        "a4": "a4",
        # x15 is argument 5
        "x15": "a5",
        "a5": "a5",
        # x16 is argument 6
        "x16": "a6",
        "a6": "a6",
        # x17 is argument 7
        "x17": "a7",
        "a7": "a7",
        # x18 is a callee-saved register
        "x18": "s2",
        "s2": "s2",
        # x19 is a callee-saved register
        "x19": "s3",
        "s3": "s3",
        # x20 is a callee-saved register
        "x20": "s4",
        "s4": "s4",
        # x21 is a callee-saved register
        "x21": "s5",
        "s5": "s5",
        # x22 is a callee-saved register
        "x22": "s6",
        "s6": "s6",
        # x23 is a callee-saved register
        "x23": "s7",
        "s7": "s7",
        # x24 is a callee-saved register
        "x24": "s8",
        "s8": "s8",
        # x25 is a callee-saved register
        "x25": "s9",
        "s9": "s9",
        # x26 is a callee-saved register
        "x26": "s10",
        "s10": "s10",
        # x27 is a callee-saved register
        "x27": "s11",
        "s11": "s11",
        # x28 is a temporary register
        "x28": "t3",
        "t3": "t3",
        # x29 is a temporary register
        "x29": "t4",
        "t4": "t4",
        # x30 is a temporary register
        "x30": "t5",
        "t5": "t5",
        # x31 is a temporary register
        "x31": "t6",
        "t6": "t6",
        # *** Program Counter ***
        "pc": "pc",
        # *** Floating-Point Registers ***
        # f0 is a temporary register
        "f0": "ft0",
        "ft0": "ft0",
        # f1 is a temporary register
        "f1": "ft1",
        "ft1": "ft1",
        # f2 is a temporary register
        "f2": "ft2",
        "ft2": "ft2",
        # f3 is a temporary register
        "f3": "ft3",
        "ft3": "ft3",
        # f4 is a temporary register
        "f4": "ft4",
        "ft4": "ft4",
        # f5 is a temporary register
        "f5": "ft5",
        "ft5": "ft5",
        # f6 is a temporary register
        "f6": "ft6",
        "ft6": "ft6",
        # f7 is a temporary register
        "f7": "ft7",
        "ft7": "ft7",
        # f8 is a callee saved register
        "f8": "fs0",
        "fs0": "fs0",
        # f9 is a callee saved register
        "f9": "fs1",
        "fs1": "fs1",
        # f10 is argument 0
        "f10": "fa0",
        "fa0": "fa0",
        # f11 is argument 1
        "f11": "fa1",
        "fa1": "fa1",
        # f12 is argument 2
        "f12": "fa2",
        "fa2": "fa2",
        # f13 is argument 3
        "f13": "fa3",
        "fa3": "fa3",
        # f14 is argument 4
        "f14": "fa4",
        "fa4": "fa4",
        # f15 is argument 5
        "f15": "fa5",
        "fa5": "fa5",
        # f16 is argument 6
        "f16": "fa6",
        "fa6": "fa6",
        # f7 is argument 7
        "f17": "fa7",
        "fa7": "fa7",
        # f18 is a callee-saved register
        "f18": "fs2",
        "fs2": "fs2",
        # f19 is a callee-saved register
        "f19": "fs3",
        "fs3": "fs3",
        # f20 is a callee-saved register
        "f20": "fs4",
        "fs4": "fs4",
        # f21 is a callee-saved register
        "f21": "fs5",
        "fs5": "fs5",
        # f22 is a callee-saved register
        "f22": "fs6",
        "fs6": "fs6",
        # f23 is a callee-saved register
        "f23": "fs7",
        "fs7": "fs7",
        # f24 is a callee-saved register
        "f24": "fs8",
        "fs8": "fs8",
        # f25 is a callee-saved register
        "f25": "fs9",
        "fs9": "fs9",
        # f26 is a callee-saved register
        "f26": "fs10",
        "fs10": "fs10",
        # f27 is a callee-saved register
        "f27": "fs11",
        "fs11": "fs11",
        # f28 is a temporary register
        "f28": "ft8",
        "ft8": "ft8",
        # f29 is a temporary register
        "f29": "ft9",
        "ft9": "ft9",
        # f30 is a temporary register
        "f30": "ft10",
        "ft10": "ft10",
        # f31 is a temporary register
        "f31": "ft11",
        "ft11": "ft11",
    }
