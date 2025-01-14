import enum
import typing

import angr
import pypcode

from ....exceptions import EmulationError
from ....platforms import Architecture, Byteorder
from .machdef import PcodeMachineDef


def handle_nop(irsb, i):
    # This op has no impact on user-facing machine state.
    irsb._ops.pop(i)
    return i


def handle_sigtrap(irsb, i):
    # This op should terminate this block with SIGTRAP
    next_addr = irsb._ops[i - 1].inputs[0].offset + 3
    irsb._ops = irsb._ops[0:i]
    irsb.next = next_addr
    irsb._size = next_addr - irsb.addr
    irsb._instruction_addresses = list(
        filter(lambda x: x < next_addr, irsb._instruction_addresses)
    )
    irsb.jumpkind = "Ijk_SigTRAP"
    return i


def handle_sigill(irsb, i):
    # This op should terminate this block with SIGILL
    next_addr = irsb._ops[i - 1].inputs[0].offset + 3
    irsb._ops = irsb._ops[0:i]
    irsb.next = next_addr
    irsb._size = next_addr - irsb.addr
    irsb._instruction_addresses = list(
        filter(lambda x: x < next_addr, irsb._instruction_addresses)
    )
    irsb.jumpkind = "Ijk_SigILL"
    return i


def handle_syscall(irsb, i):
    # This op should terminate this block with a syscall
    next_addr = irsb._ops[i - 1].inputs[0].offset + 3
    irsb._ops = irsb._ops[0:i]
    irsb.next = next_addr
    irsb._size = next_addr - irsb.addr
    irsb._instruction_addresses = list(
        filter(lambda x: x < next_addr, irsb._instruction_addresses)
    )
    irsb.jumpkind = "Ijk_Sys_syscall"

    return i


def handle_nope(irsb, i):
    # This op cannot be handled by angr
    userop = XtensaUserOp(irsb._ops[i].inputs[0].offset)
    raise EmulationError(f"Unhandled user op {userop!r}")


def handle_unimpl(irsb, i):
    # I don't know what this op does yet
    userop = XtensaUserOp(irsb._ops[i].inputs[0].offset)
    raise EmulationError(f"Unimplemented user op {userop!r}")


class UpdatedEnumMeta(enum.EnumMeta):
    def __contains__(cls, obj):
        if isinstance(obj, int):
            return obj in cls._value2member_map_
        return enum.EnumMeta.__contains__(enum.EnumMeta, obj)


class XtensaUserOp(enum.IntEnum, metaclass=UpdatedEnumMeta):
    def __new__(
        cls, val: int, name: str = "", handler: typing.Any = None, desc: str = ""
    ):
        obj = int.__new__(cls, val)
        obj._value_ = val
        obj.short_name = name
        obj.handler = handler
        obj.description = desc
        return obj

    def __init__(
        self, val: int, name: str = "", handler: typing.Any = None, desc: str = ""
    ):
        self._value_: int = val
        self.short_name: str = name
        self.handler: typing.Any = handler
        self.description: str = desc

    def __repr__(self):
        return f"{hex(self.value)}: {self.short_name} - {self.description}"

    BREAKPOINT = 0x00, "breakpoint", handle_sigtrap, "Breakpoint Instruction"
    DHI = 0x01, "dhi", handle_nop, "Data Cache Hit Invalidate"
    DHU = 0x02, "dhu", handle_nop, "Data Cache Hit Unlock"
    DHWB = 0x03, "dhwb", handle_nop, "Data Cache Hit Writeback"
    DHWBI = 0x04, "dhwbi", handle_nop, "Data Cache Hit Writeback Invalidate"
    DII = 0x05, "dii", handle_nop, "Data Cache Index Invalidate"
    DIU = 0x06, "diu", handle_nop, "Data Cache Index Unlock"
    DIWB = 0x07, "diwb", handle_nop, "Data Cache Index Writeback"
    DIWBI = 0x08, "diwbi", handle_nop, "Data Cache Index Writeback Invalidate"
    DPFL = 0x09, "dpfl", handle_nop, "Data Cache Prefetch And Lock"
    DPFR = 0x0A, "dpfr", handle_nop, "Data Cache Prefetch For Read"
    DPFRO = 0x0B, "dpfro", handle_nop, "Data Cache Prefetch For Read Once"
    DPFW = 0x0C, "dpfw", handle_nop, "Data Cache Prefetch For Write"
    DPFWO = 0x0D, "dpfwo", handle_nop, "Data Cache Prefetch For Write Once"
    DSYNC = 0x0E, "dsync", handle_nop, "Load/Store Synchronize"
    ESYNC = 0x0F, "esync", handle_nop, "Execute Synchronize"
    EXCW = 0x10, "excw", handle_sigtrap, "Exception Wait"
    EXTW = 0x11, "extw", handle_sigtrap, "External Wait"
    IDTLB = 0x12, "idtlb", handle_nop, "Invalidate Data TLB Entry"
    IHI = 0x13, "ihi", handle_nop, "Instruction Cache Hit Invalidate"
    IHU = 0x14, "ihu", handle_nop, "Instruction Cache Hit Unlock"
    III = 0x15, "iii", handle_nop, "Instruction Cache Index Invalidate"
    IITLB = 0x16, "iitlb", handle_nop, "Invalidate Instruction TLB Entry"
    IIU = 0x17, "iiu", handle_nop, "Instruction Cache Index Unlock"
    ILL = 0x18, "ill", handle_sigill, "Illegal Instruction"
    IPF = 0x19, "ipf", handle_nop, "Instruction Cache Prefetch"
    IPFL = 0x1A, "ipfl", handle_nop, "Instruction Cache Prefetch And Lock"
    ISYNC = 0x1B, "isync", handle_nop, "Instruction Fetch Synchronize"
    ACQUIRE = 0x1C, "acquire", handle_unimpl, "???"
    LDCT = 0x1D, "ldct", handle_nope, "Load Data Cache Tag"
    LICT = 0x1E, "lict", handle_nope, "Load Instruction Cache Tag"
    LICW = 0x1F, "licw", handle_nope, "Load Instruction Cache Word"
    MEMW = 0x20, "memw", handle_sigtrap, "Memory Wait"
    NSA = 0x21, "nsa", handle_unimpl, "Normalization Shift Amount"
    NSAU = 0x22, "nsau", handle_unimpl, "Normalization Shift Amount Unsigned"
    PDTLB = 0x23, "pdtlb", handle_nope, "Probe Data TLB"
    PITLB = 0x24, "pitlb", handle_nope, "Probe Instruction TLB"
    RDTLB0 = 0x25, "rdtlb0", handle_nope, "Read Data TLB Entry Virtual"
    RDTLB1 = 0x26, "rdtlb1", handle_nope, "Read Data TLB Entry Translation"
    RER = 0x27, "rer", handle_nope, "Read External Register"
    RESTORE4 = 0x28, "restore4", handle_unimpl, "???"
    RESTORE8 = 0x29, "restore8", handle_unimpl, "???"
    RESTORE12 = 0x2A, "restore12", handle_unimpl, "???"
    RFDD = 0x2B, "rfdd", handle_nope, "Return from Debug and Dispatch"
    RFDE = 0x2C, "rfde", handle_nope, "Return from Double Exception"
    RFDO = 0x2D, "rfdo", handle_nope, "Return from Debug Operation"
    RFE = 0x2E, "rfe", handle_nope, "Return from Exception"
    RFI = 0x2F, "rfi", handle_nope, "Return from Interrupt"
    RFME = 0x30, "rfme", handle_nope, "Return from Memory Error"
    RFUE = 0x31, "rfue", handle_nope, "Return from User Exception"
    RFWO = 0x32, "rfwo", handle_nope, "Return from Window Overflow"
    RFWU = 0x33, "rfwu", handle_nope, "Return from Window Underflow"
    RITLB0 = 0x34, "ritlb0", handle_nope, "Read Instruction TLB Entry Virtual"
    RITLB1 = 0x35, "ritlb1", handle_nope, "Read Instruction TLB Entry Translation"
    RSIL = 0x36, "rsil", handle_nope, "Read and Set Interrupt Level"
    RSR = 0x37, "rsr", handle_unimpl, "Read Special Register"
    RSYNC = 0x38, "rsync", handle_nop, "Register Read Synchronize"
    RUR = 0x39, "rur", handle_unimpl, "Read User Register"
    S32C1I = 0x3A, "s32c1i", handle_unimpl, "Store 32-bit compare conditional"
    RELEASE = 0x3B, "release", handle_unimpl, "???"
    RESTOREREGWINDOW = 0x3C, "restoreregwindow", handle_unimpl, "???"
    ROTATEREGWINDOW = 0x3D, "rotateregwindow", handle_unimpl, "???"
    SDCT = 0x3E, "sdct", handle_nope, "Store Data Cache Tag"
    SICT = 0x3F, "sict", handle_nope, "Store Instruction Cache Tag"
    SICW = 0x40, "sicw", handle_nope, "Store Instruction Cache Word"
    SIMCALL = 0x41, "simcall", handle_nop, "Simulator Call"
    SYSCALL = 0x42, "syscall", handle_syscall, "System Call"
    SWAP4 = 0x43, "swap4", handle_unimpl, "???"
    SWAP8 = 0x44, "swap8", handle_unimpl, "???"
    SWAP12 = 0x45, "swap12", handle_unimpl, "???"
    WAITI = 0x46, "waiti", handle_sigtrap, "Wait for Interrupt"
    WDTLB = 0x47, "wdtlb", handle_nop, "Write Data TLB Entry"
    WER = 0x48, "wer", handle_nop, "Write External Register"
    WITLB = 0x49, "witlb", handle_nop, "Write Instruction TLB Entry"
    WSR = 0x4A, "wsr", handle_unimpl, "Write Special Register"
    WUR = 0x4B, "wur", handle_unimpl, "Write User Register"
    XSR = 0x4C, "xsr", handle_unimpl, "Exchange Special Register"


# Angr doesn't have a syscall calling convention for xtensa.
# Remedy that situation.
class SimCCXtensaLinuxSyscall(angr.calling_conventions.SimCCSyscall):
    ARG_REGS = ["a6", "a3", "a4", "a5", "a8", "a9"]
    FP_ARG_REGS: typing.List[str] = []
    RETURN_VAL = angr.calling_conventions.SimRegArg("a2", 4)
    RETURN_ADDR = angr.calling_conventions.SimRegArg("ip_at_syscall", 4)
    ARCH = None

    @classmethod
    def _match(cls, arch, args, sp_data):
        # Never match; only occurs durring syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.a2


angr.calling_conventions.register_syscall_cc(
    "Xtensa:LE:32:default", "default", SimCCXtensaLinuxSyscall
)


class XTensaMachineDef(PcodeMachineDef):
    arch = Architecture.XTENSA
    _registers = {f"a{i}": f"a{i}" for i in range(0, 16)} | {"pc": "pc", "sar": "sar"}
    pc_reg = "pc"

    def successors(self, state: angr.SimState, **kwargs) -> typing.Any:
        # xtensa includes a _LOT_ of custom pcode operations.

        # Fetch or compute the IR block for our state
        if "irsb" in kwargs and kwargs["irsb"] is not None:
            # Someone's already specified an IR block.
            irsb = kwargs["irsb"]
        else:
            # Disable optimization; it doesn't work
            kwargs["opt_level"] = 0

            # Compute the block from the state.
            # Pray to the Powers that kwargs are compatible.
            irsb = state.block(**kwargs).vex

        i = 0
        while i < len(irsb._ops):
            op = irsb._ops[i]
            if op.opcode == pypcode.OpCode.CALLOTHER:
                # This is a user-defined Pcode op.
                # Alter irsb to mimic its behavior, if we can.
                opnum = op.inputs[0].offset

                if opnum not in XtensaUserOp:
                    # Not a userop.
                    raise EmulationError(f"Undefined user op {hex(opnum)}")
                # get the enum struct
                userop = XtensaUserOp(opnum)

                # Invoke the handler
                i = userop.handler(irsb, i)
            else:
                i += 1

        # Force the engine to use our IR block
        kwargs["irsb"] = irsb

        # Turn the crank on the engine
        return super().successors(state, **kwargs)


class XTensaELMachineDef(XTensaMachineDef):
    byteorder = Byteorder.LITTLE
    pcode_language = "Xtensa:LE:32:default"


class XTensaBEMachineDef(XTensaMachineDef):
    byteorder = Byteorder.BIG
    pcode_language = "Xtensa:BE:32:default"
