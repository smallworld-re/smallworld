from .... import exceptions
from ....platforms import Architecture, Byteorder
from .machdef import TritonMachineDef

# SmallWorld canonical register name -> Triton register name (RISC-V 64).
# SmallWorld carries both numeric (``x0``..``x31``, ``f0``..``f31``) and ABI
# (``ra``, ``sp``, ``a0``, ``fs0``, ...) names as separate keys; Triton's
# canonical ``getName()`` is the numeric form, so ABI aliases map onto it.
_RISCV64_REGISTERS = {
    # Program counter (pc_register == "pc" for RISC-V).
    "pc": "pc",
    "x0": "x0",
    "zero": "x0",
    "x1": "x1",
    "ra": "x1",
    "x2": "x2",
    "sp": "x2",
    "x3": "x3",
    "gp": "x3",
    "x4": "x4",
    "tp": "x4",
    "x5": "x5",
    "t0": "x5",
    "x6": "x6",
    "t1": "x6",
    "x7": "x7",
    "t2": "x7",
    "x8": "x8",
    "s0": "x8",
    "x9": "x9",
    "s1": "x9",
    "x10": "x10",
    "a0": "x10",
    "x11": "x11",
    "a1": "x11",
    "x12": "x12",
    "a2": "x12",
    "x13": "x13",
    "a3": "x13",
    "x14": "x14",
    "a4": "x14",
    "x15": "x15",
    "a5": "x15",
    "x16": "x16",
    "a6": "x16",
    "x17": "x17",
    "a7": "x17",
    "x18": "x18",
    "s2": "x18",
    "x19": "x19",
    "s3": "x19",
    "x20": "x20",
    "s4": "x20",
    "x21": "x21",
    "s5": "x21",
    "x22": "x22",
    "s6": "x22",
    "x23": "x23",
    "s7": "x23",
    "x24": "x24",
    "s8": "x24",
    "x25": "x25",
    "s9": "x25",
    "x26": "x26",
    "s10": "x26",
    "x27": "x27",
    "s11": "x27",
    "x28": "x28",
    "t3": "x28",
    "x29": "x29",
    "t4": "x29",
    "x30": "x30",
    "t5": "x30",
    "x31": "x31",
    "t6": "x31",
    "f0": "f0",
    "ft0": "f0",
    "f1": "f1",
    "ft1": "f1",
    "f2": "f2",
    "ft2": "f2",
    "f3": "f3",
    "ft3": "f3",
    "f4": "f4",
    "ft4": "f4",
    "f5": "f5",
    "ft5": "f5",
    "f6": "f6",
    "ft6": "f6",
    "f7": "f7",
    "ft7": "f7",
    "f8": "f8",
    "fs0": "f8",
    "f9": "f9",
    "fs1": "f9",
    "f10": "f10",
    "fa0": "f10",
    "f11": "f11",
    "fa1": "f11",
    "f12": "f12",
    "fa2": "f12",
    "f13": "f13",
    "fa3": "f13",
    "f14": "f14",
    "fa4": "f14",
    "f15": "f15",
    "fa5": "f15",
    "f16": "f16",
    "fa6": "f16",
    "f17": "f17",
    "fa7": "f17",
    "f18": "f18",
    "fs2": "f18",
    "f19": "f19",
    "fs3": "f19",
    "f20": "f20",
    "fs4": "f20",
    "f21": "f21",
    "fs5": "f21",
    "f22": "f22",
    "fs6": "f22",
    "f23": "f23",
    "fs7": "f23",
    "f24": "f24",
    "fs8": "f24",
    "f25": "f25",
    "fs9": "f25",
    "f26": "f26",
    "fs10": "f26",
    "f27": "f27",
    "fs11": "f27",
    "f28": "f28",
    "ft8": "f28",
    "f29": "f29",
    "ft9": "f29",
    "f30": "f30",
    "ft10": "f30",
    "f31": "f31",
    "ft11": "f31",
}


class TritonRISCV64MachineDef(TritonMachineDef):
    """Triton machine definition for RISC-V 64.

    Triton only gained RISC-V support after its last PyPI release, so builds
    older than mid-2024 lack ``ARCH.RV64``; the ``triton_arch`` property
    feature-detects it and raises a clear ``ConfigurationError`` otherwise.
    """

    arch = Architecture.RISCV64
    byteorder = Byteorder.LITTLE
    pc_register = "pc"
    sp_register = "sp"
    lr_register = "ra"
    address_size = 8
    interrupt_mnemonics = {"ecall", "ebreak"}
    _registers = _RISCV64_REGISTERS

    @property
    def triton_arch(self):
        from triton import ARCH

        if not hasattr(ARCH, "RV64"):
            raise exceptions.ConfigurationError(
                "The installed Triton build predates RISC-V support (no "
                "ARCH.RV64); rebuild Triton from a revision newer than 2024-07 "
                "to emulate RISCV64."
            )
        return ARCH.RV64
