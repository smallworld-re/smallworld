import enum
import typing

import angr
import archinfo
import pypcode

from ....exceptions import EmulationError
from ....platforms import Architecture, Byteorder
from ....platforms.defs.tricore import (
    TRICORE_INTEGER_ARGUMENT_REGISTERS,
    TRICORE_PROGRAM_COUNTER_REGISTER,
    TRICORE_POINTER_ARGUMENT_REGISTERS,
    TRICORE_REGISTER_ALIASES,
    TRICORE_RETURN_ADDRESS_REGISTER,
    TRICORE_RETURN_VALUE_REGISTER,
    TRICORE_STATUS_REGISTER,
)
from .machdef import GhidraMachineDef


class UpdatedEnumMeta(enum.EnumMeta):
    def __contains__(cls, obj):
        if isinstance(obj, int):
            return obj in cls._value2member_map_
        return enum.EnumMeta.__contains__(enum.EnumMeta, obj)


def _drop_tricore_call_frame_userop(irsb, i):
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

    SAVE_CALLER_STATE = (
        0x1E,
        "saveCallerState",
        _drop_tricore_call_frame_userop,
        "Save call context",
    )
    RESTORE_CALLER_STATE = (
        0x1F,
        "restoreCallerState",
        _drop_tricore_call_frame_userop,
        "Restore call context",
    )


def _rewrite_tricore_userops(irsb) -> tuple[bool, bool]:
    saw_save = False
    saw_restore = False

    i = 0
    while i < len(irsb._ops):
        op = irsb._ops[i]
        if op.opcode != pypcode.OpCode.CALLOTHER:
            i += 1
            continue

        opnum = op.inputs[0].offset
        if opnum not in TriCoreUserOp:
            raise EmulationError(f"Undefined user op {hex(opnum)}")

        user_op = TriCoreUserOp(opnum)
        saw_save = saw_save or user_op == TriCoreUserOp.SAVE_CALLER_STATE
        saw_restore = saw_restore or user_op == TriCoreUserOp.RESTORE_CALLER_STATE
        i = user_op.handler(irsb, i)

    return saw_save, saw_restore


def _collect_unique_successor_states(successors) -> list[angr.SimState]:
    states: list[angr.SimState] = []
    for attr in (
        "successors",
        "flat_successors",
        "unconstrained_successors",
        "unsat_successors",
    ):
        if not hasattr(successors, attr):
            continue
        for successor_state in getattr(successors, attr):
            if successor_state not in states:
                states.append(successor_state)
    return states


def _update_tricore_ra_stack(
    successor_states: list[angr.SimState],
    ra_stack: list[typing.Any],
    saved_return_address,
    saw_save: bool,
    saw_restore: bool,
) -> None:
    if saw_save:
        updated_stack = [*ra_stack, saved_return_address]
        for successor_state in successor_states:
            successor_globals = typing.cast(
                typing.MutableMapping[str, typing.Any], successor_state.globals
            )
            successor_globals["tricore_ra_stack"] = list(updated_stack)

    if saw_restore and ra_stack:
        restored_ra = ra_stack[-1]
        updated_stack = ra_stack[:-1]
        for successor_state in successor_states:
            setattr(successor_state.regs, TRICORE_RETURN_ADDRESS_REGISTER, restored_ra)
            successor_globals = typing.cast(
                typing.MutableMapping[str, typing.Any], successor_state.globals
            )
            successor_globals["tricore_ra_stack"] = list(updated_stack)


class TriCoreMachineDef(GhidraMachineDef):
    arch = Architecture.TRICORE
    byteorder = Byteorder.LITTLE
    pcode_language = "tricore:LE:32:default"
    _registers = {
        **{f"a{i}": f"a{i}" for i in range(0, 16)},
        **{f"d{i}": f"d{i}" for i in range(0, 16)},
        **TRICORE_REGISTER_ALIASES,
        TRICORE_PROGRAM_COUNTER_REGISTER: TRICORE_PROGRAM_COUNTER_REGISTER,
        TRICORE_STATUS_REGISTER: TRICORE_STATUS_REGISTER,
    }

    def successors(self, state: angr.SimState, **kwargs) -> typing.Any:
        assert hasattr(state.scratch, "exit_points")
        globals_map = typing.cast(typing.MutableMapping[str, typing.Any], state.globals)

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

        saved_return_address = getattr(state.regs, TRICORE_RETURN_ADDRESS_REGISTER)
        ra_stack = list(globals_map.get("tricore_ra_stack", ()))
        saw_save, saw_restore = _rewrite_tricore_userops(irsb)

        kwargs["irsb"] = irsb
        successors = super().successors(state, **kwargs)
        successor_states = _collect_unique_successor_states(successors)
        _update_tricore_ra_stack(
            successor_states,
            ra_stack,
            saved_return_address,
            saw_save,
            saw_restore,
        )

        return successors


class SimCCTriCore(angr.calling_conventions.SimCC):
    ARG_REGS = list(
        TRICORE_INTEGER_ARGUMENT_REGISTERS + TRICORE_POINTER_ARGUMENT_REGISTERS
    )
    FP_ARG_REGS: typing.List[str] = []
    RETURN_VAL = angr.calling_conventions.SimRegArg(TRICORE_RETURN_VALUE_REGISTER, 4)
    RETURN_ADDR = angr.calling_conventions.SimRegArg(TRICORE_RETURN_ADDRESS_REGISTER, 4)
    ARCH = archinfo.ArchPcode("tricore:LE:32:default")  # type: ignore


angr.calling_conventions.register_default_cc("tricore:LE:32:default", SimCCTriCore)
