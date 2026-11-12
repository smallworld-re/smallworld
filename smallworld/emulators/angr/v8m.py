"""Lifting ARMv8-M's stack-limit registers with VEX.

VEX can't decode M-profile msr and mrs, so pyvex hands them to its ARM
spotter, which moves only msp and primask and lifts the rest as no-ops.
archinfo's Cortex-M also has no psplim. Give ARMv8-M a psplim, and fill in
the moves for msplim and psplim after lifting.
"""

import functools
import inspect
import typing

import archinfo
import pyvex
from angr.engines import UberEngine

# The SYSm values msr and mrs use for the stack-limit registers
_STACK_LIMITS = {0x0A: "msplim", 0x0B: "psplim"}


def _offset_after(arch: archinfo.Arch) -> int:
    return max(r.vex_offset + r.size for r in arch.register_list)


def v8m_arch() -> archinfo.Arch:
    """archinfo's Cortex-M with ARMv8-M's psplim"""

    class ArchARMv8M(archinfo.ArchARMCortexM):
        # archinfo fills in the offset of a register VEX doesn't know by
        # changing the shared Register, so give psplim its own.
        register_list = archinfo.ArchARMCortexM.register_list + [
            archinfo.Register(
                name="psplim",
                size=4,
                vex_offset=_offset_after(archinfo.ArchARMCortexM()),
            )
        ]

    return ArchARMv8M()


def _decode(insn: bytes) -> typing.Optional[typing.Tuple[str, str, int]]:
    """Decode a stack-limit msr or mrs into (kind, core register, SYSm)"""
    hw1 = int.from_bytes(insn[0:2], "little")
    hw2 = int.from_bytes(insn[2:4], "little")
    sysm = hw2 & 0xFF
    if sysm not in _STACK_LIMITS:
        return None
    # msr <spec_reg>, Rn: 11110011100 0 Rn | 10 0 0 10 00 SYSm
    if hw1 & 0xFFF0 == 0xF380 and hw2 & 0xFF00 == 0x8800:
        return "msr", f"r{hw1 & 0xF}", sysm
    # mrs Rd, <spec_reg>: 1111001111101111 | 1000 Rd SYSm
    if hw1 == 0xF3EF and hw2 & 0xF000 == 0x8000:
        return "mrs", f"r{(hw2 >> 8) & 0xF}", sysm
    return None


def _moves(
    irsb: pyvex.IRSB, kind: str, core: str, sysm: int
) -> typing.List[pyvex.stmt.IRStmt]:
    arch = irsb.arch
    special = arch.get_register_offset(_STACK_LIMITS[sysm])
    tmp = irsb.tyenv.add("Ity_I32")
    if kind == "mrs":
        return [
            pyvex.stmt.WrTmp(tmp, pyvex.expr.Get(special, "Ity_I32")),
            pyvex.stmt.Put(
                pyvex.expr.RdTmp.get_instance(tmp), arch.get_register_offset(core)
            ),
        ]
    # Bits [2:0] of a stack limit are RES0.
    masked = irsb.tyenv.add("Ity_I32")
    return [
        pyvex.stmt.WrTmp(
            tmp, pyvex.expr.Get(arch.get_register_offset(core), "Ity_I32")
        ),
        pyvex.stmt.WrTmp(
            masked,
            pyvex.expr.Binop(
                "Iop_And32",
                [
                    pyvex.expr.RdTmp.get_instance(tmp),
                    pyvex.expr.Const(pyvex.const.U32(0xFFFFFFF8)),
                ],
            ),
        ),
        pyvex.stmt.Put(pyvex.expr.RdTmp.get_instance(masked), special),
    ]


def _ignored_imarks(irsb: pyvex.IRSB) -> typing.List[int]:
    """Indices of 4-byte instructions lifted to nothing"""
    stmts = irsb.statements
    return [
        i
        for i, stmt in enumerate(stmts)
        if isinstance(stmt, pyvex.stmt.IMark)
        and stmt.len == 4
        and (i + 1 == len(stmts) or isinstance(stmts[i + 1], pyvex.stmt.IMark))
    ]


# The arguments of angr's lift_vex that say where a block's bytes come from
_SOURCE_PARAMETERS = ("addr", "state", "clemory", "insn_bytes", "offset")


@functools.lru_cache(maxsize=None)
def _lift_signature(lift_vex: typing.Callable) -> inspect.Signature:
    return inspect.signature(lift_vex)


def lift_source(
    args: typing.Sequence[typing.Any],
    kwargs: typing.Mapping[str, typing.Any],
    lift_vex: typing.Callable = UberEngine.lift_vex,
) -> typing.Tuple[typing.Any, ...]:
    """The (addr, state, clemory, insn_bytes, offset) of a lift_vex call

    `args` and `kwargs` are what the engine's lift_vex was called with, less
    self. They are bound to angr's own parameters by name, so a change in
    their order can't shift them; a renamed parameter raises.
    """
    try:
        bound = _lift_signature(lift_vex).bind(None, *args, **kwargs)
    except TypeError as e:
        raise TypeError(f"angr's lift_vex parameters have changed: {e}") from e
    bound.apply_defaults()
    missing = [name for name in _SOURCE_PARAMETERS if name not in bound.arguments]
    if missing:
        raise TypeError(f"angr's lift_vex has no parameter {', '.join(missing)}")
    return tuple(bound.arguments[name] for name in _SOURCE_PARAMETERS)


def instruction_bytes(
    at: int,
    addr: int,
    state: typing.Any,
    clemory: typing.Any,
    insn_bytes: typing.Optional[bytes],
    offset: typing.Optional[int],
) -> typing.Optional[bytes]:
    """The 4 bytes at `at`, from the source angr lifted from, if it has them"""
    # angr's priority: insn_bytes (from offset, for the block's address
    # without the Thumb bit), then clemory, then state.
    try:
        if insn_bytes is not None:
            start = (offset or 0) + at - (addr & ~1)
            insn = bytes(insn_bytes[start : start + 4]) if start >= 0 else b""
        elif clemory is not None:
            insn = clemory.load(at, 4)
        elif state is not None:
            insn = state.solver.eval(state.memory.load(at, 4), cast_to=bytes)
        else:
            return None
    except KeyError:
        # Nothing mapped there in clemory
        return None
    return insn if len(insn) == 4 else None


class ARMv8MEngine(UberEngine):
    """angr's VEX engine, moving ARMv8-M's stack-limit registers"""

    def lift_vex(self, *args, **kwargs):
        irsb = super().lift_vex(*args, **kwargs)
        addr, state, clemory, insn_bytes, offset = lift_source(args, kwargs)
        if irsb.statements is None:
            return irsb
        found = []
        for index in _ignored_imarks(irsb):
            insn = instruction_bytes(
                irsb.statements[index].addr,
                irsb.addr if addr is None else addr,
                state,
                clemory,
                insn_bytes,
                offset,
            )
            decoded = None if insn is None else _decode(insn)
            if decoded is not None:
                found.append((index, decoded))
        if not found:
            return irsb
        # angr caches the lifted block, so leave its copy alone.
        irsb = irsb.copy()
        for index, decoded in reversed(found):
            irsb.statements[index + 1 : index + 1] = _moves(irsb, *decoded)
        return irsb


__all__ = ["ARMv8MEngine", "instruction_bytes", "lift_source", "v8m_arch"]
