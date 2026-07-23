"""Bridge Triton's AST into claripy via self-contained SMT-LIB2 strings.

Triton and claripy each carry their own copy of Z3 (Triton's is linked into its
native module; claripy's is the ``z3-solver`` wheel). Handing a live z3 object
from one to the other — e.g. via Triton's ``tritonToZ3`` — crashes when the two
libz3 builds differ. To stay ABI-safe we never pass a z3 object across the
boundary: Triton serialises an expression to an SMT-LIB2 *string* (pure Triton,
no z3 involved), and claripy's own z3 parses that string.

This also means the bridge does not require Triton to be built with the Z3
interface at all — it only uses ``AstContext.unroll`` and SMT-LIB stringification.

Only the Triton -> claripy direction is needed by ``TritonSymbolicEmulator``
(symbolic state is built inside Triton and read back out as claripy); there is
no claripy -> Triton path.
"""

from __future__ import annotations

import typing

import claripy
import z3


class TritonBridgeUnavailable(Exception):
    """Raised when a Triton build cannot serialise ASTs for the bridge."""


def ensure_available(astctx) -> None:
    """Raise :class:`TritonBridgeUnavailable` if the bridge can't operate.

    The SMT-LIB bridge only needs ``AstContext.unroll``; every Triton build has
    it, so this is a defensive guard rather than a real gate.
    """
    if not hasattr(astctx, "unroll"):
        raise TritonBridgeUnavailable(
            "This Triton build does not expose AstContext.unroll; the symbolic "
            "bridge to claripy cannot operate."
        )


def _declarations(ctx) -> str:
    """Emit an ``(declare-fun ...)`` line for every Triton symbolic variable.

    Triton renders a variable in SMT text by its alias when one was supplied
    (SmallWorld always supplies the claripy variable name as the alias) and by
    its ``SymVar_N`` name otherwise, so we declare both spellings; the unused one
    is harmless.
    """
    lines = []
    for var in ctx.getSymbolicVariables().values():
        size = var.getBitSize()
        emitted = set()
        for name in (var.getName(), var.getAlias()):
            if name and name not in emitted:
                emitted.add(name)
                lines.append(f"(declare-fun {name} () (_ BitVec {size}))")
    return "".join(line + "\n" for line in lines)


def _expr_smt(ctx, node) -> str:
    """Render a Triton AST node as a self-contained SMT-LIB expression string.

    ``unroll`` inlines Triton's SSA references so the result mentions only
    symbolic-variable leaves (which ``_declarations`` covers).
    """
    from triton import AST_REPRESENTATION

    unrolled = ctx.getAstContext().unroll(node)
    previous = ctx.getAstRepresentationMode()
    ctx.setAstRepresentationMode(AST_REPRESENTATION.SMT)
    try:
        return str(unrolled)
    finally:
        ctx.setAstRepresentationMode(previous)


def triton_to_claripy(ctx, node) -> typing.Any:
    """Convert a Triton ``AstNode`` into a claripy AST.

    Returns a claripy bitvector (``claripy.ast.bv.BV``) for a value expression or
    a boolean (``claripy.ast.bool.Bool``) for a predicate — hence the dynamic
    return type.
    """
    expr = _expr_smt(ctx, node)
    # Wrap as ``(= e e)`` so a single assertion carries the expression as its
    # first child, whether ``e`` is a bitvector or a boolean.
    smt = _declarations(ctx) + f"(assert (= {expr} {expr}))\n"
    assertions = z3.parse_smt2_string(smt)
    if not assertions:
        raise ValueError("Triton produced an empty SMT-LIB expression")
    return claripy.backends.z3._abstract(assertions[0].children()[0])


def triton_to_claripy_bool(ctx, node) -> claripy.ast.bool.Bool:
    """Convert a Triton predicate ``AstNode`` into a claripy boolean."""
    out = triton_to_claripy(ctx, node)
    if isinstance(out, claripy.ast.bool.Bool):
        return out
    # A 1-bit bitvector predicate: true iff equal to 1.
    return out == claripy.BVV(1, out.size())
