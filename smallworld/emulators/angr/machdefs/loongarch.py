import enum
import typing

import angr
import archinfo
import pypcode

from ....exceptions import EmulationError
from ....platforms import Architecture, Byteorder
from .machdef import GhidraMachineDef


class UpdatedEnumMeta(enum.EnumMeta):
    def __contains__(cls, obj):
        if isinstance(obj, int):
            return obj in cls._value2member_map_
        return enum.EnumMeta.__contains__(enum.EnumMeta, obj)


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


def handle_unimpl(irsb, i):
    # I don't know what this op does yet
    userop = LoongArchUserOp(irsb._ops[i].inputs[0].offset)
    raise EmulationError(f"Unimplemented user op {userop!r}")


class LoongArchUserOp(enum.IntEnum, metaclass=UpdatedEnumMeta):
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

    BREAK = 0x00, "break", handle_sigtrap, "Breakpoint instruction"
    CPUCFG = 0x01, "cpucfg", handle_unimpl, "CPU config instruction"
    ADDR_BOUND_EXCEPTION = 0x02, "addr_bound_exception", handle_unimpl, "Unknown"
    BOUND_CHECK_EXCEPTION = 0x03, "bound_check_exception", handle_unimpl, "Unknown"
    CRC_IEEE802_3 = 0x04, "crc_ieee802.3", handle_unimpl, "Unknown"
    CRC_CASTAGNOLI = 0x05, "crc_castagnoli", handle_unimpl, "Unknown"
    DBCL = 0x06, "dbcl", handle_unimpl, "Unknown"
    DBAR = 0x07, "dbar", handle_nop, "Data Barrier"
    IBAR = 0x08, "ibar", handle_nop, "Instruction Barrier"
    IOCSRRD = 0x09, "iocsrrd", handle_unimpl, "Unknown"
    IOCSRWR = 0x0A, "iocsrwr", handle_unimpl, "Unknown"
    PRELD_LOADL1CACHE = 0x0B, "preld_loadl1cache", handle_unimpl, "Unknown"
    PRELD_STOREL1CACHE = 0x0C, "preld_storel1cache", handle_unimpl, "Unknown"
    PRELD_NOP = 0x0D, "preld_nop", handle_unimpl, "Unknown"
    PRELDX_LOADL1CACHE = 0x0E, "preldx_loadl1cache", handle_unimpl, "Unknown"
    PRELDX_STOREL1CACHE = 0x0F, "preldx_storel1cache", handle_unimpl, "Unknown"
    PRELDX_NOP = 0x10, "preldx_nop", handle_unimpl, "Unknown"
    RDTIME_COUNTER = 0x11, "rdtime.counter", handle_unimpl, "Unknown"
    RDTIME_COUNTERID = 0x12, "rdtime.counterid", handle_unimpl, "Unknown"
    SYSCALL = 0x13, "syscall", handle_syscall, "Unknown"
    F_SCALEB = 0x14, "f_scaleb", handle_unimpl, "Unknown"
    F_LOGB = 0x15, "f_logb", handle_unimpl, "Unknown"
    F_CLASS = 0x16, "f_class", handle_unimpl, "Unknown"
    ROUND_EVEN = 0x17, "round_even", handle_unimpl, "Unknown"


class LoongArchMachineDef(GhidraMachineDef):
    byteorder = Byteorder.LITTLE

    _registers = {
        "pc": "pc",
        # Zero register
        "r0": "zero",
        "zero": "zero",
        # Return address
        "r1": "ra",
        "ra": "ra",
        # TLS pointer
        "r2": "tp",
        "tp": "tp",
        # Stack pointer
        "r3": "sp",
        "sp": "sp",
        # Arguments.
        # a0 and a1 are also the return registers
        "r4": "a0",
        "a0": "a0",
        "v0": "a0",
        "r5": "a1",
        "a1": "a1",
        "v1": "a1",
        "r6": "a2",
        "a2": "a2",
        "r7": "a3",
        "a3": "a3",
        "r8": "a4",
        "a4": "a4",
        "r9": "a5",
        "a5": "a5",
        "r10": "a6",
        "a6": "a6",
        "r11": "a7",
        "a7": "a7",
        # Temporary registers
        "r12": "t0",
        "t0": "t0",
        "r13": "t1",
        "t1": "t1",
        "r14": "t2",
        "t2": "t2",
        "r15": "t3",
        "t3": "t3",
        "r16": "t4",
        "t4": "t4",
        "r17": "t5",
        "t5": "t5",
        "r18": "t6",
        "t6": "t6",
        "r19": "t7",
        "t7": "t7",
        "r20": "t8",
        "t8": "t8",
        # Per-CPU Base Address
        "r21": "r21",
        "u0": "r21",
        # Frame Pointer
        "r22": "fp",
        "fp": "fp",
        # Static registers
        "r23": "s0",
        "s0": "s0",
        "r24": "s1",
        "s1": "s1",
        "r25": "s2",
        "s2": "s2",
        "r26": "s3",
        "s3": "s3",
        "r27": "s4",
        "s4": "s4",
        "r28": "s5",
        "s5": "s5",
        "r29": "s6",
        "s6": "s6",
        "r30": "s7",
        "s7": "s7",
        "r31": "s8",
        "s8": "s8",
        # Floating-point arguments.
        # fa0 and fa1 are also return values
        "f0": "fa0",
        "fa0": "fa0",
        "f1": "fa1",
        "fa1": "fa1",
        "f2": "fa2",
        "fa2": "fa2",
        "f3": "fa3",
        "fa3": "fa3",
        "f4": "fa4",
        "fa4": "fa4",
        "f5": "fa5",
        "fa5": "fa5",
        "f6": "fa6",
        "fa6": "fa6",
        "f7": "fa7",
        "fa7": "fa7",
        # Floating-point temporary registers
        "f8": "ft0",
        "ft0": "ft0",
        "f9": "ft1",
        "ft1": "ft1",
        "f10": "ft2",
        "ft2": "ft2",
        "f11": "ft3",
        "ft3": "ft3",
        "f12": "ft4",
        "ft4": "ft4",
        "f13": "ft5",
        "ft5": "ft5",
        "f14": "ft6",
        "ft6": "ft6",
        "f15": "ft7",
        "ft7": "ft7",
        "f16": "ft8",
        "ft8": "ft8",
        "f17": "ft9",
        "ft9": "ft9",
        "f18": "ft10",
        "ft10": "ft10",
        "f19": "ft11",
        "ft11": "ft11",
        "f20": "ft12",
        "ft12": "ft12",
        "f21": "ft13",
        "ft13": "ft13",
        "f22": "ft14",
        "ft14": "ft14",
        "f23": "ft15",
        "ft15": "ft15",
        # Floating-point static registers
        "f24": "fs0",
        "fs0": "fs0",
        "f25": "fs1",
        "fs1": "fs1",
        "f26": "fs2",
        "fs2": "fs2",
        "f27": "fs3",
        "fs3": "fs3",
        "f28": "fs4",
        "fs4": "fs4",
        "f29": "fs5",
        "fs5": "fs5",
        "f30": "fs6",
        "fs6": "fs6",
        "f31": "fs7",
        "fs7": "fs7",
    }

    def successors(self, state: angr.SimState, **kwargs) -> typing.Any:
        # Inject exit points here.
        if "extra_stop_points" in kwargs:
            exit_points = state.scratch.exit_points | set(kwargs["extra_stop_points"])
            del kwargs["extra_stop_points"]
        else:
            exit_points = state.scratch.exit_points

        # Fetch or compute the IR block for our state
        if "irsb" in kwargs and kwargs["irsb"] is not None:
            # Someone's already specified an IR block.
            irsb = kwargs["irsb"]
        else:
            # Disable optimization; it doesn't work
            kwargs["opt_level"] = 0

            # Compute the block from the state.
            # Pray to the Powers that kwargs are compatible.
            irsb = state.block(extra_stop_points=exit_points, **kwargs).vex

        i = 0
        while i < len(irsb._ops):
            op = irsb._ops[i]
            if op.opcode == pypcode.OpCode.CALLOTHER:
                # This is a user-defined Pcode op.
                # Alter irsb to mimic its behavior, if we can.
                opnum = op.inputs[0].offset

                if opnum not in LoongArchUserOp:
                    # Not a userop.
                    raise EmulationError(f"Undefined user op {hex(opnum)}")
                # get the enum struct
                userop = LoongArchUserOp(opnum)

                # Invoke the handler
                i = userop.handler(irsb, i)
            else:
                i += 1

        # Force the engine to use our IR block
        kwargs["irsb"] = irsb

        # Turn the crank on the engine
        return super().successors(state, **kwargs)


class SimCCLoongArchLinux(angr.calling_conventions.SimCC):
    ARG_REGS = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
    FP_ARG_REGS = ["fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7"]
    RETURN_VAL = angr.calling_conventions.SimRegArg("a0", 8)
    RETURN_ADDR = angr.calling_conventions.SimRegArg("ra", 8)
    ARCH = archinfo.ArchPcode("Loongarch:LE:64:lp64d")  # type: ignore


angr.calling_conventions.register_default_cc(
    "Loongarch:LE:64:lp64d", SimCCLoongArchLinux
)


class SimCCLoongArchLinuxSyscall(angr.calling_conventions.SimCCSyscall):
    ARG_REGS = ["a0", "a1", "a2", "a3", "a4", "a5"]
    FP_ARG_REGS: typing.List[str] = []
    RETURN_VAL = angr.calling_conventions.SimRegArg("a0", 8)
    RETURN_ADDR = angr.calling_conventions.SimRegArg("ip_at_syscall", 8)
    ARCH = None

    @classmethod
    def _match(cls, arch, args, sp_data):
        # Never match; only occurs durring syscalls
        return False

    @staticmethod
    def syscall_num(state):
        # This is a massive guess from RE'ing libc
        return state.regs.a7


angr.calling_conventions.register_syscall_cc(
    "Loongarch:LE:64:lp64d", "default", SimCCLoongArchLinuxSyscall
)


class LoongArch64MachineDef(LoongArchMachineDef):
    arch = Architecture.LOONGARCH64
    pcode_language = "Loongarch:LE:64:lp64d"


__all__ = ["LoongArch64MachineDef"]
