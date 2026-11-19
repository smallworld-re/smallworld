import typing

import angr
import pypcode

from ....platforms import Architecture, Byteorder
from ....platforms.defs import PowerPC32VLE
from .machdef import GhidraMachineDef
from .pcode_rewrite import lift_for_rewrite, pcode_arch, rewrite_as_syscall

PPC_VLE_PCODE_LANGUAGE = "PowerPC:BE:32:e200"

# `se_sc` and `e_sc` both lift to this user op.
PPC_SYSCALL_USEROP = "syscall"

# User ops that only order memory accesses or manage caches. With no cache
# or pipeline to model, they have no effect on the state, so they are
# dropped. `dcbz` (dataCacheBlockClearToZero), `dcba`, `stwcx.`, `wrtee`,
# the TLB writes and the interrupt returns change state and still raise.
PPC_VLE_NOP_USEROPS = frozenset(
    {
        # msync/sync, mbar 0 (eieio), mbar 1, se_isync, tlbsync
        "sync",
        "enforceInOrderExecutionIO",
        "memoryBarrier",
        "instructionSynchronize",
        "TLBSynchronize",
        # dcbf, dcbst, dcbi, dcbt, dcbtst, icbi, icbt
        "dataCacheBlockFlush",
        "dataCacheBlockStore",
        "dataCacheBlockInvalidate",
        "dataCacheBlockTouch",
        "dataCacheBlockTouchForStore",
        "instructionCacheBlockInvalidate",
        "instructionCacheBlockTouch",
    }
)

# The registers the e200 language has, by SmallWorld name. The language
# names the special-purpose registers without the `spr_` prefix. It also
# defines f0-f31, which the e200 lacks and SmallWorld leaves out.
_E200_REGISTERS: typing.Dict[str, typing.Optional[str]] = {
    **{f"r{i}": f"r{i}" for i in range(32)},
    "sp": "r1",
    "bp": "r31",
    "pc": "pc",
    "lr": "lr",
    "ctr": "ctr",
    **{f"cr{i}": f"cr{i}" for i in range(8)},
    "msr": "msr",
    "spr_srr0": "srr0",
    "spr_srr1": "srr1",
    "spr_csrr0": "csrr0",
    "spr_csrr1": "csrr1",
    # The language keeps XER's bits in separate registers (xer_so, xer_ov,
    # xer_ca, ...) and only assembles them on mfxer, so its `xer` register
    # does not hold the live value.
    "spr_xer": None,
    # The same registers as lr and ctr; they are reached by those names, as
    # on the powerpc32 machine.
    "spr_lr": None,
    "spr_ctr": None,
}


class PowerPC32VLEMachineDef(GhidraMachineDef):
    """angr machine definition for PowerPC e200 with VLE, using p-code.

    VEX, which runs the other PowerPC machines, has no VLE decoder. The
    p-code comes from pypcode's own `PowerPC:BE:32:e200` language, which
    pypcode builds on Ghidra's VLE sleigh; upstream Ghidra has no 32-bit
    e200 language.
    """

    arch = Architecture.POWERPC32_VLE
    byteorder = Byteorder.BIG
    pcode_language = PPC_VLE_PCODE_LANGUAGE

    _registers: typing.Dict[str, typing.Optional[str]] = {  # type: ignore[assignment]
        # The remaining special-purpose registers are not in the language.
        **{name: None for name in PowerPC32VLE().registers},
        **_E200_REGISTERS,
    }

    def successors(self, state: angr.SimState, **kwargs) -> typing.Any:
        """Drop barrier and cache user ops, and surface `se_sc` and `e_sc`
        as syscalls.

        angr's p-code engine rejects every user op. Those in
        `PPC_VLE_NOP_USEROPS` have no effect here, so they are removed.
        Sleigh lifts both syscall instructions to the `syscall` user op, and
        p-code has no syscall jump kind of its own. As on SH-4 (see
        `machdefs/superh4.py`), the block is cut after the trap's IMARK and
        ends in Ijk_Sys_syscall, resuming after the trap. User ops are
        matched by name, not by index, which a Ghidra update could reorder.
        """
        irsb = lift_for_rewrite(state, kwargs)

        irsb._ops = [
            op
            for op in irsb._ops
            if op.opcode != pypcode.OpCode.CALLOTHER
            or op.inputs[0].getUserDefinedOpName() not in PPC_VLE_NOP_USEROPS
        ]

        imark = None
        for i, op in enumerate(irsb._ops):
            if op.opcode == pypcode.OpCode.IMARK:
                imark = i
                continue
            if op.opcode != pypcode.OpCode.CALLOTHER:
                continue
            if op.inputs[0].getUserDefinedOpName() != PPC_SYSCALL_USEROP:
                continue
            if imark is None:
                # The lifter emits an IMARK before every instruction.
                break
            # se_sc is 2 bytes and e_sc is 4; the IMARK knows which.
            trap = irsb._ops[imark].inputs[0]
            rewrite_as_syscall(irsb, imark + 1, trap.offset + trap.size)
            break

        kwargs["irsb"] = irsb
        return super().successors(state, **kwargs)


class SimCCPowerPC32VLE(angr.calling_conventions.SimCC):
    """PowerPC EABI calling convention.

    Integer arguments go in r3 through r10, results come back in r3 (and
    r4), and the return address is in lr. Stack arguments start at sp + 8,
    after the back chain and the LR save word, and the stack is 8-byte
    aligned.
    """

    STACKARG_SP_BUFF = 8
    STACK_ALIGNMENT = 8
    ARG_REGS = [f"r{i}" for i in range(3, 11)]
    FP_ARG_REGS: typing.List[str] = []
    RETURN_VAL = angr.calling_conventions.SimRegArg("r3", 4)
    OVERFLOW_RETURN_VAL = angr.calling_conventions.SimRegArg("r4", 4)
    RETURN_ADDR = angr.calling_conventions.SimRegArg("lr", 4)
    ARCH = pcode_arch(PPC_VLE_PCODE_LANGUAGE)  # type: ignore


class SimCCPowerPC32VLESyscall(angr.calling_conventions.SimCCSyscall):
    """PowerPC syscall convention, following the Linux PPC32 syscall ABI.

    The number is in r0, up to six arguments are in r3 through r8, and the
    result is in r3. (angr's powerpc32 machine, on VEX, takes arguments in
    r3 through r10.)
    """

    ARG_REGS = [f"r{i}" for i in range(3, 9)]
    FP_ARG_REGS: typing.List[str] = []
    RETURN_VAL = angr.calling_conventions.SimRegArg("r3", 4)
    # ArchPcode has no ip_at_syscall; SyscallHookProcedure resumes at
    # state._ip, which the rewrite already set past the trap. See
    # `SimCCSuperHLinuxSyscall`.
    RETURN_ADDR = angr.calling_conventions.SimRegArg("ip_at_syscall", 4)
    ARCH = pcode_arch(PPC_VLE_PCODE_LANGUAGE)  # type: ignore

    @classmethod
    def _match(cls, arch, args, sp_data):
        # Never match by inference; this convention only applies to syscalls.
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.r0


angr.calling_conventions.register_default_cc(PPC_VLE_PCODE_LANGUAGE, SimCCPowerPC32VLE)
angr.calling_conventions.register_syscall_cc(
    PPC_VLE_PCODE_LANGUAGE, "default", SimCCPowerPC32VLESyscall
)
