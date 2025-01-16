import typing

import angr
import archinfo

from ....platforms import Architecture, Byteorder
from .machdef import AngrMachineDef

# angr has no default calling convention for RISCV64
# Let's fix that.


class SimCCRISCV64(angr.calling_conventions.SimCC):
    ARG_REGS = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
    FP_ARG_REGS = ["fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7"]
    RETURN_VAL = angr.calling_conventions.SimRegArg("a0", 8)
    RETURN_ADDR = angr.calling_conventions.SimRegArg("ra", 8)
    # angr doesn't type this field correctly
    ARCH = archinfo.ArchRISCV64  # type: ignore[assignment]


angr.calling_conventions.register_default_cc("RISCV64", SimCCRISCV64)

# angr ALSO has no default syscall calling convention for RISCV64
# Let's fix that


class SimCCRISCV64LinuxSyscall(angr.calling_conventions.SimCCSyscall):
    # Since the RISCV peeps don't seem to have written their kernel ABI,
    # I RE'd the syscall convention from glibc.
    # It looks like they use the same arg and return regs,
    # except that they repurpose a7 as the syscall number.
    ARG_REGS = ["a0", "a1", "a2", "a3", "a4", "a5", "a6"]
    FP_ARG_REGS: typing.List[str] = []
    RETURN_VAL = angr.calling_conventions.SimRegArg("a0", 8)
    RETURN_ADDR = angr.calling_conventions.SimRegArg("ip_at_syscall", 4)
    # angr doesn't type this field correctly
    ARCH = archinfo.ArchRISCV64  # type: ignore[assignment]

    @classmethod
    def _match(cls, arch, args, sp_data):
        # Never match; only occurs durring syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.a7


angr.calling_conventions.register_syscall_cc(
    "RISCV64", "default", SimCCRISCV64LinuxSyscall
)


class RISCV64MachineDef(AngrMachineDef):
    arch = Architecture.RISCV64
    byteorder = Byteorder.LITTLE

    angr_arch = archinfo.ArchRISCV64()

    pc_reg = "pc"

    _registers = {
        # *** General-Purpose Registers ***
        # x0 is wired to 0, and aliased as "zero"
        "x0": "x0",
        "zero": "zero",
        # x1 acts as the link register
        # NOTE: ra is the official name; lr might be an angr invention.
        "x1": "x1",
        "ra": "ra",
        # x2 acts as the stack pointer
        "x2": "x2",
        "sp": "sp",
        # x3 acts as the global pointer
        "x3": "x3",
        "gp": "gp",
        # x4 acts as the thread pointer
        "x4": "x4",
        "tp": "tp",
        # x5 is a temporary register
        "x5": "x5",
        "t0": "t0",
        # x6 is a temporary register
        "x6": "x6",
        "t1": "t1",
        # x7 is a temporary register
        "x7": "x7",
        "t2": "t2",
        # x8 is a callee-saved register
        "x8": "x8",
        "s0": "s0",
        # x9 is a callee-saved register
        "x9": "x9",
        "s1": "s1",
        # x10 is argument 0
        "x10": "x10",
        "a0": "a0",
        # x11 is argument 1
        "x11": "x11",
        "a1": "a1",
        # x12 is argument 2
        "x12": "x12",
        "a2": "a2",
        # x13 is argument 3
        "x13": "x13",
        "a3": "a3",
        # x14 is argument 4
        "x14": "x14",
        "a4": "a4",
        # x15 is argument 5
        "x15": "x15",
        "a5": "a5",
        # x16 is argument 6
        "x16": "x16",
        "a6": "a6",
        # x17 is argument 7
        "x17": "x17",
        "a7": "a7",
        # x18 is a callee-saved register
        "x18": "x18",
        "s2": "s2",
        # x19 is a callee-saved register
        "x19": "x19",
        "s3": "s3",
        # x20 is a callee-saved register
        "x20": "x20",
        "s4": "s4",
        # x21 is a callee-saved register
        "x21": "x21",
        "s5": "s5",
        # x22 is a callee-saved register
        "x22": "x22",
        "s6": "s6",
        # x23 is a callee-saved register
        "x23": "x23",
        "s7": "s7",
        # x24 is a callee-saved register
        "x24": "x24",
        "s8": "s8",
        # x25 is a callee-saved register
        "x25": "x25",
        "s9": "s9",
        # x26 is a callee-saved register
        "x26": "x26",
        "s10": "s10",
        # x27 is a callee-saved register
        "x27": "x27",
        "s11": "s11",
        # x28 is a temporary register
        "x28": "x28",
        "t3": "t3",
        # x29 is a temporary register
        "x29": "x29",
        "t4": "t4",
        # x30 is a temporary register
        "x30": "x30",
        "t5": "t5",
        # x31 is a temporary register
        "x31": "x31",
        "t6": "t6",
        # *** Program Counter ***
        "pc": "pc",
        # *** Floating-Point Registers ***
        # f0 is a temporary register
        "f0": "f0",
        "ft0": "ft0",
        # f1 is a temporary register
        "f1": "f1",
        "ft1": "ft1",
        # f2 is a temporary register
        "f2": "f2",
        "ft2": "ft2",
        # f3 is a temporary register
        "f3": "f3",
        "ft3": "ft3",
        # f4 is a temporary register
        "f4": "f4",
        "ft4": "ft4",
        # f5 is a temporary register
        "f5": "f5",
        "ft5": "ft5",
        # f6 is a temporary register
        "f6": "f6",
        "ft6": "ft6",
        # f7 is a temporary register
        "f7": "f7",
        "ft7": "ft7",
        # f8 is a callee saved register
        "f8": "f8",
        "fs0": "fs0",
        # f9 is a callee saved register
        "f9": "f9",
        "fs1": "fs1",
        # f10 is argument 0
        "f10": "f10",
        "a0": "a0",
        # f11 is argument 1
        "f11": "f11",
        "a1": "a1",
        # f12 is argument 2
        "f12": "f12",
        "a2": "a2",
        # f13 is argument 3
        "f13": "f13",
        "a3": "a3",
        # f14 is argument 4
        "f14": "f14",
        "a4": "a4",
        # f15 is argument 5
        "f15": "f15",
        "a5": "a5",
        # f16 is argument 6
        "f16": "f16",
        "a6": "a6",
        # f7 is argument 7
        "f17": "f17",
        "a7": "a7",
        # f18 is a callee-saved register
        "f18": "f18",
        "fs2": "fs2",
        # f19 is a callee-saved register
        "f19": "f19",
        "fs3": "fs3",
        # f20 is a callee-saved register
        "f20": "f20",
        "fs4": "fs4",
        # f21 is a callee-saved register
        "f21": "f21",
        "fs5": "fs5",
        # f22 is a callee-saved register
        "f22": "f22",
        "fs6": "fs6",
        # f23 is a callee-saved register
        "f23": "f23",
        "fs7": "fs7",
        # f24 is a callee-saved register
        "f24": "f24",
        "fs8": "fs8",
        # f25 is a callee-saved register
        "f25": "f25",
        "fs9": "fs9",
        # f26 is a callee-saved register
        "f26": "f26",
        "fs10": "fs10",
        # f27 is a callee-saved register
        "f27": "f27",
        "fs11": "fs11",
        # f28 is a temporary register
        "f28": "f28",
        "ft8": "ft8",
        # f29 is a temporary register
        "f29": "f29",
        "ft9": "ft9",
        # f30 is a temporary register
        "f30": "f30",
        "ft10": "ft10",
        # f31 is a temporary register
        "f31": "f31",
        "ft11": "ft11",
    }
