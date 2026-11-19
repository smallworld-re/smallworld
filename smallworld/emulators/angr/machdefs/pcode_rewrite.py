"""Helpers for p-code machine definitions that rewrite lifted blocks.

angr's p-code lifter derives a block's jumpkind from its last p-code op, so
it can only produce Ijk_Boring, Ijk_Call, Ijk_Ret or Ijk_NoDecode. Sleigh has
no syscall or trap opcode; it lowers those instructions to a userop
(CALLOTHER) or models them as plain machine state. A machine definition that
wants angr to see a syscall or a signal overrides
:meth:`AngrMachineDef.successors`, lifts the block with
:func:`lift_for_rewrite`, finds the instruction, and ends the block there
with :func:`rewrite_as_syscall`.
"""

import functools
import typing

import angr
import archinfo
import pypcode


@functools.lru_cache(maxsize=None)
def pcode_arch(language: str) -> archinfo.arch.Arch:
    """One shared ``ArchPcode`` per sleigh language.

    ``archinfo.ArchPcode.__init__`` re-runs ``pypcode.Arch.enumerate()`` and
    rebuilds the whole register table every time, roughly 8 ms per call, and
    archinfo does not memoize it. The ``SimCC`` classes only ever read from
    ``ARCH``, so they can share one object per language. The cost is paid
    during ``import smallworld``, on every platform, because
    ``machdefs/__init__.py`` imports every machine definition eagerly.
    """
    return archinfo.ArchPcode(language)


def lift_for_rewrite(state: angr.SimState, kwargs: typing.Dict[str, typing.Any]):
    """Lift the block at ``state``'s PC so it can be inspected and rewritten.

    Mirrors the prologue of :meth:`AngrMachineDef.successors`: exit points
    are folded into the lift and removed from ``kwargs`` (which this
    mutates), because they end up baked into the block handed back to the
    engine. If ``kwargs`` already names a block, that block is returned.

    This does not set ``opt_level``; angr's p-code lifter ignores it.
    """
    assert hasattr(state.scratch, "exit_points")

    if kwargs.get("irsb") is not None:
        # Someone already decided which block to run.
        return kwargs["irsb"]

    if "extra_stop_points" in kwargs:
        exit_points = state.scratch.exit_points | set(kwargs.pop("extra_stop_points"))
    else:
        exit_points = state.scratch.exit_points

    return state.block(extra_stop_points=exit_points, **kwargs).vex


def rewrite_as_syscall(
    irsb, keep: int, next_addr: int, jumpkind: str = "Ijk_Sys_syscall"
) -> None:
    """End ``irsb`` with ``jumpkind``, continuing at ``next_addr``.

    The default jumpkind makes angr treat the block's end as a syscall;
    ``Ijk_SigTRAP`` and ``Ijk_SigILL`` raise a signal instead.

    ``keep`` is the number of leading p-code ops to retain: everything up to
    and including the trapping instruction's IMARK, and none of the
    instruction's own semantics. Ops for earlier instructions in the same
    block must survive; they may set up the syscall number.

    ``keep`` must include the trapping instruction's own IMARK. Without it, a
    trap at the start of a block leaves a block with zero ops, and angr then
    hands the syscall a state whose ``_ip`` is still the trap itself.
    ``SyscallHookProcedure`` jumps to ``state._ip``, so execution returns to
    the trap and loops forever.
    """
    assert keep > 0, "block rewrite must retain the trapping instruction's IMARK"
    irsb._ops = irsb._ops[0:keep]
    irsb.next = next_addr
    irsb._size = next_addr - irsb.addr
    # `_instruction_addresses` is `list[int] | None`: `IRSB.extend()` calls
    # `_set_attributes` without it, so a block stitched together from several
    # lifter passes has None here while still carrying the concatenated ops.
    if irsb._instruction_addresses is not None:
        irsb._instruction_addresses = [
            addr for addr in irsb._instruction_addresses if addr < next_addr
        ]
    irsb.jumpkind = jumpkind


def find_pcode_relative_branch(irsb) -> typing.Optional[int]:
    """The address of the first instruction in ``irsb`` that branches within
    its own p-code, or None.

    Sleigh lowers an instruction with an if/else in its semantics to a
    ``BRANCH`` or ``CBRANCH`` whose target is in the constant space: an
    offset into the instruction's own p-code. angr's p-code engine can't run
    those; it fails an assertion when the branch is taken, and runs both
    arms when it isn't.
    """
    address = None
    for op in irsb._ops:
        if op.opcode == pypcode.OpCode.IMARK:
            address = op.inputs[0].offset
        elif (
            op.opcode in (pypcode.OpCode.BRANCH, pypcode.OpCode.CBRANCH)
            and op.inputs[0].space.name == "const"
        ):
            assert address is not None
            return address
    return None
