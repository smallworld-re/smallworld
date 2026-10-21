import typing

import angr
import archinfo
import claripy
import pypcode

from ....platforms import Architecture, Byteorder
from ....platforms.defs.sparc import (
    SPARC_FRAME_POINTER_REGISTER,
    SPARC_RETURN_ADDRESS_OFFSET,
    SPARC_RETURN_ADDRESS_REGISTER,
    SPARC_STACK_POINTER_REGISTER,
    SPARC_WINDOW_REGISTERS,
)
from .machdef import GhidraMachineDef

SPARC32_PCODE_LANGUAGE = "sparc:BE:32:default"

# Ghidra's SPARC `save` and `restore` copy the current window's %i and %l
# registers to and from a backing bank of registers, indexed by CWP.  Both
# skip that copy when the DECOMPILE_MODE register is set -- a hint for the
# decompiler, which wants calls to look like they preserve nothing -- so it
# must be 0 when executing.  angr fills uninitialized registers with fresh
# symbols, which would fork every `save` on a symbolic DECOMPILE_MODE and
# store to a symbolic bank address on a symbolic CWP.
_DECOMPILE_MODE = "decompile_mode"
_CWP = "cwp"


class _ConstVarnode:
    """A constant p-code input.

    pypcode cannot construct varnodes, and angr's p-code engine reads only
    `space.name`, `offset` and `size` from a constant, so this stands in for
    one.
    """

    def __init__(self, like: pypcode.Varnode, value: int):
        self.space = like.space
        self.offset = value
        self.size = like.size

    def __str__(self):
        return hex(self.offset)


class _PatchedOp:
    """A p-code op with some inputs replaced.

    pypcode ops are read-only, and angr's p-code engine reads only `opcode`,
    `inputs` and `output` from one, so this stands in for the original.
    """

    def __init__(self, op: pypcode.PcodeOp, inputs: typing.List[typing.Any]):
        self.opcode = op.opcode
        self.inputs = inputs
        self.output = op.output
        self._original = op

    def __str__(self):
        return f"{self._original} (patched by SmallWorld)"

    __repr__ = __str__


def _register_name(varnode: typing.Any) -> typing.Optional[str]:
    if varnode is None or varnode.space.name != "register":
        return None
    return varnode.getRegisterName().lower()


def _is_cwp_times_window_size(op: typing.Any) -> bool:
    return (
        op.opcode == pypcode.OpCode.INT_MULT
        and _register_name(op.inputs[0]) == _CWP
        and op.inputs[1].space.name == "const"
    )


def _window_slot_add(
    ops: typing.List[typing.Any], defs: typing.Dict[int, int], address: typing.Any
) -> typing.Optional[int]:
    """The index of the op adding a window slot to CWP * window size.

    Walks the computation of a bank address back to `CWP * 16 + slot`, the
    INT_ADD whose second input is the constant slot number.
    """
    pending = [address]
    while pending:
        varnode = pending.pop()
        if varnode.space.name != "unique" or varnode.offset not in defs:
            continue
        index = defs[varnode.offset]
        op = ops[index]
        if (
            op.opcode == pypcode.OpCode.INT_ADD
            and op.inputs[1].space.name == "const"
            and op.inputs[0].space.name == "unique"
            and op.inputs[0].offset in defs
            and _is_cwp_times_window_size(ops[defs[op.inputs[0].offset]])
        ):
            return index
        pending.extend(op.inputs)
    return None


def _fix_window_copies(irsb) -> None:
    """Correct Ghidra's register-window bank copies in a lifted block.

    Ghidra 12.1.2's `save` stores %l3 in %l2's bank slot, and its `restore`
    loads %l7 from %l6's slot, so %l2 and %l7 come back wrong after a call.
    Each local's slot is `CWP * 16 + n + 8` for %ln; make every store of a
    local store the register its slot belongs to, and every load of a local
    read that register's slot.  Ops that are already right are left alone,
    so a block can be fixed more than once.
    """
    ops = irsb._ops
    locals_by_name: typing.Dict[str, typing.Any] = {}
    for op in ops:
        for varnode in (op.output, *op.inputs):
            name = _register_name(varnode)
            if name is not None and name.startswith("l"):
                locals_by_name.setdefault(name, varnode)

    defs: typing.Dict[int, int] = {}
    for index, op in enumerate(ops):
        if op.opcode == pypcode.OpCode.IMARK:
            # unique space offsets are only meaningful within an instruction.
            defs = {}
            continue
        if op.output is not None and op.output.space.name == "unique":
            defs[op.output.offset] = index

        if op.opcode == pypcode.OpCode.STORE:
            name = _register_name(op.inputs[2])
            if name is None or not name.startswith("l"):
                continue
            slot_index = _window_slot_add(ops, defs, op.inputs[1])
            if slot_index is None:
                continue
            want = f"l{ops[slot_index].inputs[1].offset}"
            if want != name and want in locals_by_name:
                ops[index] = _PatchedOp(
                    op, [op.inputs[0], op.inputs[1], locals_by_name[want]]
                )

        elif op.opcode == pypcode.OpCode.LOAD:
            name = _register_name(op.output)
            if name is None or not name.startswith("l"):
                continue
            slot_index = _window_slot_add(ops, defs, op.inputs[1])
            if slot_index is None:
                continue
            slot_op = ops[slot_index]
            want_slot = int(name[1:])
            if slot_op.inputs[1].offset != want_slot:
                ops[slot_index] = _PatchedOp(
                    slot_op,
                    [slot_op.inputs[0], _ConstVarnode(slot_op.inputs[1], want_slot)],
                )


def _drop_ops_after_calls(irsb) -> None:
    """Remove the p-code a `call` runs after its CALL op.

    Ghidra follows a direct `call`'s CALL with a check of `didrestore`,
    returning straight to %o7 when the delay slot was a `restore`.  That
    models the `call; restore` tail-call idiom for the decompiler; execution
    never gets past the CALL, which transfers control.  angr's p-code engine
    keeps executing after a CALL, and turns that check into a second
    successor at the fall-through, so drop it.
    """
    ops = irsb._ops
    kept = []
    skipping = False
    for op in ops:
        if op.opcode == pypcode.OpCode.IMARK:
            skipping = False
        elif skipping:
            continue
        kept.append(op)
        if op.opcode in (pypcode.OpCode.CALL, pypcode.OpCode.CALLIND):
            skipping = True
    if len(kept) != len(ops):
        irsb._ops = kept


class SPARC32MachineDef(GhidraMachineDef):
    """angr machine definition for 32-bit SPARC, using Ghidra's p-code.

    The register windows behave as Ghidra models them: unbounded, with no
    overflow or underflow traps.  `successors` adjusts each lifted block so
    that angr executes it the way Ghidra's own emulator does; see
    `_DECOMPILE_MODE`, `_drop_ops_after_calls` and `_fix_window_copies`.
    """

    arch = Architecture.SPARC32
    byteorder = Byteorder.BIG
    pcode_language = SPARC32_PCODE_LANGUAGE

    _registers = {
        **{name: name for name in SPARC_WINDOW_REGISTERS},
        # Ghidra names r14 and r30 only by their ABI roles.
        SPARC_STACK_POINTER_REGISTER: "sp",
        SPARC_FRAME_POINTER_REGISTER: "fp",
        "sp": "sp",
        "fp": "fp",
        "pc": "pc",
        "npc": "npc",
        "y": "y",
    }

    def successors(self, state: angr.SimState, **kwargs) -> typing.Any:
        assert hasattr(state.scratch, "exit_points")
        state.registers.store(_DECOMPILE_MODE, claripy.BVV(0, 8))
        if state.registers.load(_CWP).symbolic:
            state.registers.store(_CWP, claripy.BVV(0, 32))

        if kwargs.get("irsb") is None:
            exit_points = state.scratch.exit_points | set(
                kwargs.get("extra_stop_points", ())
            )
            lift_kwargs = {k: v for k, v in kwargs.items() if k != "extra_stop_points"}
            lift_kwargs["opt_level"] = 0
            kwargs["irsb"] = state.block(
                extra_stop_points=exit_points, **lift_kwargs
            ).vex
        _drop_ops_after_calls(kwargs["irsb"])
        _fix_window_copies(kwargs["irsb"])

        return super().successors(state, **kwargs)


class SimCCSPARC32(angr.calling_conventions.SimCC):
    """SPARC V8 calling convention, per Ghidra's ``SparcV9_32.cspec``."""

    ARG_REGS = [f"o{i}" for i in range(0, 6)]
    FP_ARG_REGS: typing.List[str] = []
    # Stack arguments start past the 16-word window save area and the hidden
    # struct-return word.
    STACKARG_SP_BUFF = 68
    STACK_ALIGNMENT = 8
    RETURN_VAL = angr.calling_conventions.SimRegArg("o0", 4)
    RETURN_ADDR = angr.calling_conventions.SimRegArg(SPARC_RETURN_ADDRESS_REGISTER, 4)
    ARCH = archinfo.ArchPcode(SPARC32_PCODE_LANGUAGE)  # type: ignore

    def teardown_callsite(self, state, *args, **kwargs):
        # %o7 holds the address of the call itself; a function returns past
        # the call and its delay slot.  SmallWorld's function hooks return
        # through here.
        ret_addr = super().teardown_callsite(state, *args, **kwargs)
        if ret_addr is None:
            return None
        return ret_addr + SPARC_RETURN_ADDRESS_OFFSET


angr.calling_conventions.register_default_cc(SPARC32_PCODE_LANGUAGE, SimCCSPARC32)
