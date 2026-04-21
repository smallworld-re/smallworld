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
    # The TriCore call-frame userops update context state we do not model.
    irsb._ops.pop(i)
    return i


class TriCoreUserOp(enum.IntEnum, metaclass=UpdatedEnumMeta):
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

    SAVE_CALLER_STATE = 0x1E, "saveCallerState", handle_nop, "Save call context"
    RESTORE_CALLER_STATE = 0x1F, "restoreCallerState", handle_nop, "Restore call context"


class TriCoreMachineDef(GhidraMachineDef):
    arch = Architecture.TRICORE
    byteorder = Byteorder.LITTLE
    pcode_language = "tricore:LE:32:default"
    _registers = {
        **{f"a{i}": f"a{i}" for i in range(0, 16)},
        **{f"d{i}": f"d{i}" for i in range(0, 16)},
        "pc": "pc",
        "psw": "psw",
        "sp": "sp",
        "ra": "a11",
        "lr": "a11",
    }

    def successors(self, state: angr.SimState, **kwargs) -> typing.Any:
        assert hasattr(state.scratch, "exit_points")

        if "extra_stop_points" in kwargs:
            exit_points = state.scratch.exit_points | set(kwargs["extra_stop_points"])
            del kwargs["extra_stop_points"]
        else:
            exit_points = state.scratch.exit_points

        if "irsb" in kwargs and kwargs["irsb"] is not None:
            irsb = kwargs["irsb"]
        else:
            kwargs["opt_level"] = 0
            irsb = state.block(extra_stop_points=exit_points, **kwargs).vex

        saved_ra = state.regs.a11
        ra_stack = list(state.globals.get("tricore_ra_stack", ()))
        saw_save = False
        saw_restore = False

        i = 0
        while i < len(irsb._ops):
            op = irsb._ops[i]
            if op.opcode == pypcode.OpCode.CALLOTHER:
                opnum = op.inputs[0].offset
                if opnum not in TriCoreUserOp:
                    raise EmulationError(f"Undefined user op {hex(opnum)}")
                if opnum == TriCoreUserOp.SAVE_CALLER_STATE:
                    saw_save = True
                elif opnum == TriCoreUserOp.RESTORE_CALLER_STATE:
                    saw_restore = True
                i = TriCoreUserOp(opnum).handler(irsb, i)
            else:
                i += 1

        kwargs["irsb"] = irsb
        successors = super().successors(state, **kwargs)

        successor_states = []
        for attr in (
            "successors",
            "flat_successors",
            "unconstrained_successors",
            "unsat_successors",
        ):
            if not hasattr(successors, attr):
                continue
            for successor_state in getattr(successors, attr):
                if successor_state not in successor_states:
                    successor_states.append(successor_state)

        if saw_save:
            updated_stack = [*ra_stack, saved_ra]
            for successor_state in successor_states:
                successor_state.globals["tricore_ra_stack"] = list(updated_stack)

        if saw_restore and ra_stack:
            restored_ra = ra_stack[-1]
            updated_stack = ra_stack[:-1]
            for successor_state in successor_states:
                successor_state.regs.a11 = restored_ra
                successor_state.globals["tricore_ra_stack"] = list(updated_stack)

        return successors


class SimCCTriCore(angr.calling_conventions.SimCC):
    ARG_REGS = ["d4", "d5", "d6", "d7", "a4", "a5", "a6", "a7"]
    FP_ARG_REGS: typing.List[str] = []
    RETURN_VAL = angr.calling_conventions.SimRegArg("d2", 4)
    RETURN_ADDR = angr.calling_conventions.SimRegArg("a11", 4)
    ARCH = archinfo.ArchPcode("tricore:LE:32:default")  # type: ignore


angr.calling_conventions.register_default_cc("tricore:LE:32:default", SimCCTriCore)
