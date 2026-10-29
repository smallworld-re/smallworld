import typing

import angr
import archinfo
import pypcode

from ....platforms import Architecture, Byteorder
from ....platforms.defs import PowerPC32VLE
from .machdef import GhidraMachineDef
from .superh import lift_for_rewrite, rewrite_as_syscall

PPC_VLE_PCODE_LANGUAGE = "PowerPC:BE:32:e200"

# `se_sc` and `e_sc` both lift to this user op.
PPC_SYSCALL_USEROP = "syscall"


class PowerPC32VLEMachineDef(GhidraMachineDef):
    """angr machine definition for PowerPC e200 with VLE, using Ghidra's
    p-code.

    VEX, which runs the other PowerPC machines, has no VLE decoder. The
    e200 language decodes VLE by default and names its registers as
    SmallWorld does.
    """

    arch = Architecture.POWERPC32_VLE
    byteorder = Byteorder.BIG
    pcode_language = PPC_VLE_PCODE_LANGUAGE

    _registers: typing.Dict[str, typing.Optional[str]] = {  # type: ignore[assignment]
        **{name: name for name in PowerPC32VLE().registers},
        "sp": "r1",
        "bp": "r31",
        # NOTE: The Ghidra machine definition leaves msr out too.
        "msr": None,
    }

    def successors(self, state: angr.SimState, **kwargs) -> typing.Any:
        """Surface `se_sc` and `e_sc` as syscalls.

        Sleigh lifts both to the `syscall` user op, which angr's p-code engine
        rejects, and p-code has no syscall jump kind of its own. As on SH-4
        (see `machdefs/superh4.py`), the block is cut after the trap's IMARK
        and ends in Ijk_Sys_syscall, resuming after the trap. The op is
        matched by name, not by index, which a Ghidra update could reorder.
        """
        irsb = lift_for_rewrite(state, kwargs)

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
    r4), and the return address is in lr.
    """

    ARG_REGS = [f"r{i}" for i in range(3, 11)]
    FP_ARG_REGS: typing.List[str] = []
    RETURN_VAL = angr.calling_conventions.SimRegArg("r3", 4)
    OVERFLOW_RETURN_VAL = angr.calling_conventions.SimRegArg("r4", 4)
    RETURN_ADDR = angr.calling_conventions.SimRegArg("lr", 4)
    ARCH = archinfo.ArchPcode(PPC_VLE_PCODE_LANGUAGE)  # type: ignore


class SimCCPowerPC32VLESyscall(angr.calling_conventions.SimCCSyscall):
    """PowerPC syscall convention, as angr's VEX PowerPC32 uses it.

    The number is in r0, arguments in r3 through r8, and the result in r3.
    """

    ARG_REGS = [f"r{i}" for i in range(3, 9)]
    FP_ARG_REGS: typing.List[str] = []
    RETURN_VAL = angr.calling_conventions.SimRegArg("r3", 4)
    # ArchPcode has no ip_at_syscall; SyscallHookProcedure resumes at
    # state._ip, which the rewrite already set past the trap. See
    # `SimCCSuperHLinuxSyscall`.
    RETURN_ADDR = angr.calling_conventions.SimRegArg("ip_at_syscall", 4)
    ARCH = archinfo.ArchPcode(PPC_VLE_PCODE_LANGUAGE)  # type: ignore

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
