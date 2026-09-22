"""Linear symbolic emulator backed by Triton's symbolic engine.

Triton is a single-path concolic engine: it maintains concrete and symbolic
state side by side and follows exactly one path, choosing branch directions from
the concrete state. :class:`TritonSymbolicEmulator` therefore models *linear*
symbolic execution, exactly like ``GhidraSymbolicEmulator`` — ``enable_branching``
raises and ``get_active_states`` yields a single state.

Symbolic values cross the boundary to SmallWorld (which speaks claripy) through
:mod:`smallworld.emulators.triton.z3bridge`, which serialises a Triton AST to an
SMT-LIB2 string and re-parses it with claripy's own Z3 (never passing a live z3
object across the two libz3 builds). Constraints are held as claripy and solved
with a ``claripy.Solver`` (like the angr and Ghidra backends), seeded with both
user-supplied constraints and the path predicate Triton accumulates.
"""

from __future__ import annotations

import typing

import claripy

from ... import exceptions
from .. import emulator
from . import z3bridge
from .triton import MemoryAccess, TritonEmulator

# Sizes, in bytes, that Triton's MemoryAccess accepts.
_ACCESS_SIZES = (64, 32, 16, 8, 4, 2, 1)


def _is_access_size(size: int) -> bool:
    return size in _ACCESS_SIZES


def _access_chunks(address: int, size: int) -> typing.List[typing.Tuple[int, int]]:
    """Split ``size`` bytes at ``address`` into MemoryAccess-sized pieces.

    Greedy largest-first, so an 11-byte buffer becomes 8 + 2 + 1 rather than
    eleven separate byte accesses.
    """
    chunks: typing.List[typing.Tuple[int, int]] = []
    offset = address
    remaining = size
    while remaining:
        for candidate in _ACCESS_SIZES:
            if candidate <= remaining:
                break
        chunks.append((offset, candidate))
        offset += candidate
        remaining -= candidate
    return chunks


class TritonSymbolicEmulator(
    TritonEmulator,
    emulator.ConstrainedEmulator,
    emulator.SymbolicEmulator,
):
    """Symbolic (linear) emulator backend for SmallWorld based on Triton."""

    name = "triton-symbolic"
    description = (
        "linear symbolic emulator based on the Triton dynamic binary analysis framework"
    )
    version = "0.1.0"

    def __init__(self, platform):
        super().__init__(platform)
        # The claripy bridge only needs AstContext.unroll (a defensive check).
        try:
            z3bridge.ensure_available(self.ctx.getAstContext())
        except z3bridge.TritonBridgeUnavailable as e:
            raise exceptions.ConfigurationError(str(e)) from e

        self._user_constraints: typing.List[claripy.ast.bool.Bool] = []
        self._symbolic_inputs: typing.Dict[str, claripy.ast.bv.BV] = {}
        self._linear: bool = True
        # Registers the harness has explicitly written (concrete or symbolic),
        # keyed by *parent* register so that "pc"/"rip" and "edi"/"rdi" name the
        # same entry. Used by write_register_label to decide whether a label
        # should pin the register to its prior value: Triton reads an unwritten
        # register as a concrete 0, so — unlike angr, whose unset registers are
        # fresh symbols — we must not treat that default 0 as a value to bind
        # the label to.
        self._written_registers: typing.Set[str] = set()

    # ------------------------------------------------------ symbolic register I/O

    def _write_symbolic_register(
        self, reg: typing.Any, name: str, bv: claripy.ast.bv.BV
    ) -> None:
        if not bv.symbolic:
            self.ctx.setConcreteRegisterValue(reg, bv.concrete_value)
            return
        if bv.op == "BVS":
            varname = list(bv.variables)[0]
            self.ctx.symbolizeRegister(reg, z3bridge.smt_symbol(varname))
            self._symbolic_inputs[varname] = bv
        else:
            # Compound expression: symbolize the register with a fresh variable
            # and bind it to the desired expression via a constraint.
            self.ctx.symbolizeRegister(reg)
            reg_bv = z3bridge.triton_to_claripy(self.ctx, self.ctx.getRegisterAst(reg))
            self._user_constraints.append(reg_bv == bv)

    def _write_symbolic_memory(self, address: int, bv: claripy.ast.bv.BV) -> None:
        if bv.size() % 8:
            raise exceptions.SymbolicValueError(
                f"Cannot write a {bv.size()}-bit value to memory at "
                f"{hex(address)}; memory values must be a whole number of bytes"
            )
        size = bv.size() // 8
        # A write implies a mapping, exactly as it does on the concrete path
        # (``TritonEmulator.write_memory_content``). Record it *before* touching
        # Triton: symbolizing a cell reads it first, which would otherwise fault
        # against a map that does not know about the region yet.
        self._memory_map.add_range((address, address + size))
        if not bv.symbolic:
            data = int(bv.concrete_value).to_bytes(size, self._byteorder())
            self.ctx.setConcreteMemoryAreaValue(address, data, False)
            return
        with self._direct_access():
            if _is_access_size(size):
                mem = MemoryAccess(address, size)
                if bv.op == "BVS":
                    varname = list(bv.variables)[0]
                    self.ctx.symbolizeMemory(mem, z3bridge.smt_symbol(varname))
                    self._symbolic_inputs[varname] = bv
                else:
                    self.ctx.symbolizeMemory(mem)
                    mem_bv = z3bridge.triton_to_claripy(
                        self.ctx, self.ctx.getMemoryAst(mem)
                    )
                    self._user_constraints.append(mem_bv == bv)
                return
            # Triton's MemoryAccess only takes power-of-two sizes, so a wider or
            # odd-sized buffer is symbolized in chunks and tied back to the
            # caller's expression with constraints, one slice per chunk.
            if bv.op == "BVS":
                self._symbolic_inputs[list(bv.variables)[0]] = bv
            for offset, chunk in _access_chunks(address, size):
                mem = MemoryAccess(offset, chunk)
                self.ctx.symbolizeMemory(mem)
                mem_bv = z3bridge.triton_to_claripy(
                    self.ctx, self.ctx.getMemoryAst(mem)
                )
                self._user_constraints.append(
                    mem_bv == self._slice(bv, address, offset, chunk)
                )

    def _register_key(self, name: str) -> str:
        """The parent register ``name`` belongs to, as a stable identity.

        SmallWorld reaches one physical register through several names ("pc"
        and "rip", "edi" and "rdi"), so anything keyed on the caller's spelling
        would treat them as unrelated.
        """
        return str(self.ctx.getParentRegister(self._reg(name)).getName())

    def write_register_content(
        self, name: str, content: typing.Union[None, int, claripy.ast.bv.BV]
    ) -> None:
        if content is not None:
            self._written_registers.add(self._register_key(name))
        if isinstance(content, claripy.ast.bv.BV) and content.symbolic:
            self._write_symbolic_register(self._reg(name), name, content)
        elif isinstance(content, claripy.ast.bv.BV):
            # A concrete bitvector is just an integer with a width; hand it to
            # the base so the ARM32 Thumb-bit handling and the register-name
            # checks apply to it exactly as they do to a plain int.
            super().write_register_content(name, content.concrete_value)
        else:
            # None / int (and thumb handling) are dealt with by the concrete base.
            super().write_register_content(name, content)

    def write_memory_content(
        self, address: int, content: typing.Union[bytes, claripy.ast.bv.BV]
    ) -> None:
        if isinstance(content, claripy.ast.bv.BV):
            self._write_symbolic_memory(address, content)
        else:
            super().write_memory_content(address, content)

    def read_register_symbolic(self, name: str) -> claripy.ast.bv.BV:
        node = self.ctx.getRegisterAst(self._reg(name))
        return z3bridge.triton_to_claripy(self.ctx, node)

    def read_memory_symbolic(self, address: int, size: int) -> claripy.ast.bv.BV:
        with self._direct_access():
            if _is_access_size(size):
                node = self.ctx.getMemoryAst(MemoryAccess(address, size))
                return z3bridge.triton_to_claripy(self.ctx, node)
            # As in _write_symbolic_memory: read in power-of-two chunks and glue
            # them back together in memory order.
            parts = [
                z3bridge.triton_to_claripy(
                    self.ctx, self.ctx.getMemoryAst(MemoryAccess(offset, chunk))
                )
                for offset, chunk in _access_chunks(address, size)
            ]
        if self._byteorder() == "little":
            # Chunk 0 holds the least significant bytes, and Concat is MSB-first.
            parts.reverse()
        return claripy.Concat(*parts)

    def _slice(
        self, bv: claripy.ast.bv.BV, base: int, offset: int, size: int
    ) -> claripy.ast.bv.BV:
        """The part of ``bv`` that lives in ``size`` bytes at ``offset``."""
        if self._byteorder() == "little":
            low = (offset - base) * 8
        else:
            low = bv.size() - (offset - base + size) * 8
        return bv[low + size * 8 - 1 : low]

    def read_register_content(self, name: str) -> int:
        reg = self._reg(name)
        if self.ctx.isRegisterSymbolized(reg):
            raise exceptions.SymbolicValueError(
                f"Register '{name}' contains a symbolic value"
            )
        return int(self.ctx.getConcreteRegisterValue(reg))

    def read_memory_content(self, address: int, size: int) -> bytes:
        # Not gated on "did the harness write a symbolic value": memory also
        # becomes symbolic by *execution* (a symbolized register spilled to the
        # stack), and returning Triton's concrete shadow for that would hand the
        # caller a silently wrong value instead of routing it through
        # read_memory_symbolic. Checked in MemoryAccess-sized chunks rather than
        # byte by byte -- isMemorySymbolized is true if any covered byte is.
        for offset, chunk in _access_chunks(address, size):
            if self.ctx.isMemorySymbolized(MemoryAccess(offset, chunk)):
                raise exceptions.SymbolicValueError(
                    f"Memory at {hex(address)} (size {size}) is symbolic"
                )
        return bytes(self.ctx.getConcreteMemoryAreaValue(address, size, False))

    # --------------------------------------------------------------- labels

    def write_register_label(
        self, name: str, label: typing.Optional[str] = None
    ) -> None:
        if label is None:
            return
        reg = self._reg(name)
        size_bits = reg.getBitSize()
        bv = claripy.BVS(label, size_bits, explicit_name=True)
        # Bind the label to the register's prior value only if the harness
        # actually wrote one (angr/Ghidra discipline); a never-written register
        # reads as Triton's default 0, which must stay a free symbol, not get
        # pinned to 0.
        if self._register_key(name) in self._written_registers:
            prev = self.read_register_symbolic(name)
            if not (prev.symbolic and prev.op == "BVS"):
                self._user_constraints.append(prev == bv)
        self._symbolic_inputs[label] = bv
        self.write_register_content(name, bv)

    def write_memory_label(
        self, address: int, size: int, label: typing.Optional[str] = None
    ) -> None:
        if label is None:
            return
        prev = self.read_memory_symbolic(address, size)
        bv = claripy.BVS(label, size * 8, explicit_name=True)
        if not (prev.symbolic and prev.op == "BVS"):
            self._user_constraints.append(prev == bv)
        self._symbolic_inputs[label] = bv
        self.write_memory_content(address, bv)

    # ------------------------------------------------------- ConstrainedEmulator

    def add_constraint(self, expr: claripy.ast.bool.Bool) -> None:
        self._user_constraints.append(expr)

    def _path_constraints(self) -> typing.List[claripy.ast.bool.Bool]:
        """Lift Triton's accumulated path predicate into claripy.

        Failures are *not* swallowed: dropping the path predicate would leave
        ``satisfiable``/``eval_atmost`` answering from the user's constraints
        alone, which is unsound rather than merely incomplete.
        """
        try:
            node = self.ctx.getPathPredicate()
            predicate = z3bridge.triton_to_claripy_bool(self.ctx, node)
        except Exception as e:
            raise exceptions.SymbolicValueError(
                f"Could not lift Triton's path predicate into claripy: {e}"
            ) from e
        # A trivially-true predicate (no branches yet) adds nothing useful.
        if predicate.op == "BoolV" and predicate.is_true():
            return []
        return [predicate]

    def get_constraints(self) -> typing.List[claripy.ast.bool.Bool]:
        return list(self._user_constraints) + self._path_constraints()

    def _solver(
        self, extras: typing.Sequence[claripy.ast.bool.Bool] = ()
    ) -> "claripy.Solver":
        solver = claripy.Solver()
        for expr in self.get_constraints():
            solver.add(expr)
        for expr in extras:
            solver.add(expr)
        return solver

    def satisfiable(
        self,
        extra_constraints: typing.List[claripy.ast.bool.Bool] = [],
    ) -> bool:
        return self._solver(extra_constraints).satisfiable()

    def eval_atmost(self, expr: claripy.ast.bv.BV, most: int) -> typing.List[int]:
        solver = self._solver()
        try:
            results = list(solver.eval(expr, most + 1))
        except claripy.errors.UnsatError as exc:
            raise exceptions.UnsatError(
                "No satisfying assignment for expression given constraints"
            ) from exc
        if not results:
            raise exceptions.UnsatError(
                "No satisfying assignment for expression given constraints"
            )
        if len(results) > most:
            raise exceptions.SymbolicValueError(
                f"More than {most} solutions for expression"
            )
        return results

    def eval_atleast(self, expr: claripy.ast.bv.BV, least: int) -> typing.List[int]:
        solver = self._solver()
        try:
            results = list(solver.eval(expr, least))
        except claripy.errors.UnsatError as exc:
            raise exceptions.SymbolicValueError(
                f"Fewer than {least} solutions for expression"
            ) from exc
        if len(results) < least:
            raise exceptions.SymbolicValueError(
                f"Fewer than {least} solutions for expression"
            )
        return results

    # --------------------------------------------------------- SymbolicEmulator

    def _no_symbolic_hooks(self, what: str) -> typing.NoReturn:
        raise exceptions.ConfigurationError(
            f"TritonSymbolicEmulator does not implement {what}: Triton's memory "
            f"callbacks carry concrete values only, so there is no symbolic hook "
            f"path to route them through. Use AngrEmulator or "
            f"GhidraSymbolicEmulator for symbolic MMIO."
        )

    def hook_memory_read_symbolic(self, start, end, function) -> None:
        self._no_symbolic_hooks("symbolic memory-read hooks")

    def hook_memory_reads_symbolic(self, function) -> None:
        self._no_symbolic_hooks("symbolic memory-read hooks")

    def hook_memory_write_symbolic(self, start, end, function) -> None:
        self._no_symbolic_hooks("symbolic memory-write hooks")

    def hook_memory_writes_symbolic(self, function) -> None:
        self._no_symbolic_hooks("symbolic memory-write hooks")

    def enable_branching(self) -> None:
        raise NotImplementedError(
            "TritonSymbolicEmulator only supports linear execution; Triton is a "
            "single-path concolic engine and does not fork states."
        )

    def get_active_states(self) -> typing.Generator[emulator.Emulator, None, None]:
        # Linear execution: this emulator is itself the single active state.
        yield self

    def get_deadended_states(self) -> typing.Generator[emulator.Emulator, None, None]:
        return
        yield  # pragma: no cover - makes this a generator

    def __repr__(self) -> str:
        return f"TritonSymbolicEmulator(platform={self.platform})"


__all__ = ["TritonSymbolicEmulator"]
