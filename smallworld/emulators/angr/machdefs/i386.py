import typing

import angr
import archinfo
import pyvex

from ....platforms import Architecture, Byteorder
from .machdef import AngrMachineDef


class i386MachineDef(AngrMachineDef):
    arch = Architecture.X86_32
    byteorder = Byteorder.LITTLE

    angr_arch = archinfo.arch_x86.ArchX86()

    pc_reg = "eip"

    _registers = {
        # *** General Purpose Registers ***
        "eax": "eax",
        "ax": "ax",
        "al": "al",
        "ah": "ah",
        "ebx": "ebx",
        "bx": "bx",
        "bl": "bl",
        "bh": "bh",
        "ecx": "ecx",
        "cx": "cx",
        "cl": "cl",
        "ch": "ch",
        "edx": "edx",
        "dx": "dx",
        "dl": "dl",
        "dh": "dh",
        "esi": "esi",
        "si": "si",
        "sil": "sil",
        "edi": "edi",
        "di": "di",
        "dil": "dil",
        "ebp": "ebp",
        "bp": "bp",
        "bpl": "bpl",
        "esp": "esp",
        "sp": "sp",
        "spl": "spl",
        # *** Instruction Pointer ***
        "eip": "eip",
        "ip": "ip",
        # *** Segment Registers ***
        "cs": "cs",
        "ds": "ds",
        "es": "es",
        "fs": "fs",
        "gs": "gs",
        "ss": "ss",
        # *** Flags Register ***
        "eflags": "eflags",
        "flags": "flags",
        # *** Control Registers ***
        "cr0": "",
        "cr1": "",
        "cr2": "",
        "cr3": "",
        "cr4": "",
        "cr8": "",
        # *** Debug Registers ***
        "dr0": "",
        "dr1": "",
        "dr2": "",
        "dr3": "",
        "dr6": "",
        "dr7": "",
        # *** Descriptor Table Registers ***
        "gdtr": "gdt",
        "idtr": "idt",
        "ldtr": "ldt",
        # *** Task Register ***
        "tr": "",
        # *** x87 Registers ***
        # TODO: angr seems to support x87, but I have no idea how its register file works
        # I can't find most of the control registers,
        # and there don't seem to be separate "fprN" registers; just one giant blob
        "fpr0": "",
        "fpr1": "",
        "fpr2": "",
        "fpr3": "",
        "fpr4": "",
        "fpr5": "",
        "fpr6": "",
        "fpr7": "",
        "fctrl": "",
        "fstat": "",
        "ftag": "fptag",
        "fip": "",
        "fdp": "",
        "fop": "",
        # *** MMX Registers ***
        "mm0": "mm0",
        "mm1": "mm1",
        "mm2": "mm2",
        "mm3": "mm3",
        "mm4": "mm4",
        "mm5": "mm5",
        "mm6": "mm6",
        "mm7": "mm7",
        # *** SSE Registers ***
        "xmm0": "xmm0",
        "xmm1": "xmm1",
        "xmm2": "xmm2",
        "xmm3": "xmm3",
        "xmm4": "xmm4",
        "xmm5": "xmm5",
        "xmm6": "xmm6",
        "xmm7": "xmm7",
    }

    def rebuild_irsb(self, addr, good_bytes):
        # Lift good_bytes to an IRSB
        return pyvex.lift(good_bytes, addr, self.angr_arch)

    def build_sysexit_irsb(self, insn, good_bytes):
        # Build a new IRSB just containing sysexit:
        # 0: IMARK (addr, 2, 0)
        # 1: t0 = GET:I32(ecx)
        # 2: t1 = GET:I32(edx)
        # 3: PUT(esp) = t0
        # NEXT: PUT(eip) = t1; Iji_Sys_sysexit

        # Get the offsetfs of ecd and edx
        ecx_off, _ = self.angr_arch.registers["ecx"]
        edx_off, _ = self.angr_arch.registers["edx"]
        esp_off, _ = self.angr_arch.registers["esp"]

        # Type environment; we need two variables of type int32
        irsb_tyenv = pyvex.IRTypeEnv(self.angr_arch, ["Ity_I32", "Ity_I32"])

        # Statements
        irsb_stmts = [
            # Statement 0: Instruction mark
            pyvex.stmt.IMark(insn.address, 2, 0),
            # Statement 1: Load ecx into t0
            pyvex.stmt.WrTmp(
                0,  # Load into t0
                pyvex.expr.Get(  # Get a register
                    ecx_off,
                    "Ity_I32",
                ),
            ),
            # Statement 2: Load edx into t1
            pyvex.stmt.WrTmp(
                1,  # Load into t1
                pyvex.expr.Get(  # Get a register
                    edx_off,
                    "Ity_I32",
                ),
            ),
            # Statement 3: Load t0 into esp
            pyvex.stmt.Put(pyvex.expr.RdTmp.get_instance(0), esp_off),
        ]

        # "next" expression; Value of t1
        irsb_next = pyvex.expr.RdTmp.get_instance(1)
        # Jump kind
        irsb_jumpkind = "Ijk_Boring"

        irsb = pyvex.IRSB.from_py(
            irsb_tyenv,
            irsb_stmts,
            irsb_next,
            irsb_jumpkind,
            insn.address,
            self.angr_arch,
        )
        if len(good_bytes) > 0:
            prefix = self.rebuild_irsb(insn.address - len(good_bytes), good_bytes)
            # Fuse the two together
            irsb = prefix.extend(irsb)

        return irsb

    def successors(self, state: angr.SimState, **kwargs) -> typing.Any:
        # VEX doesn't correctly model SYSENTER and SYSEXIT

        # Fetch or compute the IR block for our state
        if "irsb" in kwargs and kwargs["irsb"] is not None:
            # Someone's already specified an IR block.
            irsb = kwargs["irsb"]
        else:
            # Disable optimization; it doesn't work

            # Compute the block from the state
            # Pray to the Powers that kwargs are compatible.
            irsb = state.block(**kwargs).vex

        if irsb.jumpkind == "Ijk_NoDecode":
            # VEX is stumped regarding this instruction.
            # Unfortunately, this also means basic block detection failed.
            irsb = None
            disas = state.block(**kwargs).disassembly
            good_bytes = b""
            for insn in disas.insns:
                if insn.mnemonic == "sysexit":
                    irsb = self.build_sysexit_irsb(insn, good_bytes)
                    break
                else:
                    good_bytes += insn.insn.bytes
            if irsb is None:
                irsb = self.rebuild_irsb(disas.insns[0].address, good_bytes)

        # Force the engine to use our IR block
        kwargs["irsb"] = irsb

        # Turn the crank on the engine
        try:
            return super().successors(state, **kwargs)
        except angr.errors.SimIRSBNoDecodeError as e:
            print(f"Bad IRSB:\n{irsb}")
            raise e
