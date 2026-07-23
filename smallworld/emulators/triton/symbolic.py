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
        self._memory_symbolized: bool = False
        self._linear: bool = True
        # Registers the harness has explicitly written (concrete or symbolic).
        # Used by write_register_label to decide whether a label should pin the
        # register to its prior value: Triton reads an unwritten register as a
        # concrete 0, so — unlike angr, whose unset registers are fresh symbols —
        # we must not treat that default 0 as a value to bind the label to.
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
            self.ctx.symbolizeRegister(reg, varname)
            self._symbolic_inputs[varname] = bv
        else:
            # Compound expression: symbolize the register with a fresh variable
            # and bind it to the desired expression via a constraint.
            self.ctx.symbolizeRegister(reg)
            reg_bv = z3bridge.triton_to_claripy(self.ctx, self.ctx.getRegisterAst(reg))
            self._user_constraints.append(reg_bv == bv)

    def _write_symbolic_memory(self, address: int, bv: claripy.ast.bv.BV) -> None:
        size = bv.size() // 8
        if not bv.symbolic:
            data = int(bv.concrete_value).to_bytes(size, self._byteorder())
            self.ctx.setConcreteMemoryAreaValue(address, data, False)
            return
        mem = MemoryAccess(address, size)
        if bv.op == "BVS":
            varname = list(bv.variables)[0]
            self.ctx.symbolizeMemory(mem, varname)
            self._symbolic_inputs[varname] = bv
        else:
            self.ctx.symbolizeMemory(mem)
            mem_bv = z3bridge.triton_to_claripy(self.ctx, self.ctx.getMemoryAst(mem))
            self._user_constraints.append(mem_bv == bv)
        self._memory_symbolized = True

    def write_register_content(
        self, name: str, content: typing.Union[None, int, claripy.ast.bv.BV]
    ) -> None:
        if content is not None:
            self._written_registers.add(name.lower())
        if isinstance(content, claripy.ast.bv.BV):
            self._write_symbolic_register(self._reg(name), name, content)
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
        node = self.ctx.getMemoryAst(MemoryAccess(address, size))
        return z3bridge.triton_to_claripy(self.ctx, node)

    def read_register_content(self, name: str) -> int:
        reg = self._reg(name)
        if self.ctx.isRegisterSymbolized(reg):
            raise exceptions.SymbolicValueError(
                f"Register '{name}' contains a symbolic value"
            )
        return int(self.ctx.getConcreteRegisterValue(reg))

    def read_memory_content(self, address: int, size: int) -> bytes:
        if self._memory_symbolized:
            for offset in range(size):
                if self.ctx.isMemorySymbolized(MemoryAccess(address + offset, 1)):
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
        if name.lower() in self._written_registers:
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
        """Lift Triton's accumulated path predicate into claripy."""
        try:
            node = self.ctx.getPathPredicate()
            predicate = z3bridge.triton_to_claripy_bool(self.ctx, node)
        except Exception:
            return []
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
