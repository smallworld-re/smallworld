"""SMT-LIB bridge between claripy and Ghidra's Java Z3.

Both sides ultimately use Microsoft Z3, but each has its own AST representation:
a Python ``z3``/claripy AST on the Python side, and a ``com.microsoft.z3.Context``
on the JVM side. We exchange expressions as SMT-LIB2 strings so neither side
holds a reference to the other's native object.

Ghidra's ``SymZ3MemoryMap`` synthesizes byte-level memory loads as applications
of an uninterpreted function family named ``load_<addressSize>_<dataSize>``
(see ``ghidra.pcode.emu.symz3.SymZ3MemoryMap#buildLoad``). Claripy's z3 backend
has no entry for these custom decls and raises ``UnboundLocalError`` when its
``_abstract_internal`` walker hits one. We sidestep that here by replacing
every such UF application with a fresh ``z3.BitVec`` leaf — different argument
forms get different placeholders, identical AST nodes share a placeholder.

The Java-side helpers expect a ``jctx`` (``com.microsoft.z3.Context``) and
return JPype-wrapped Java types. They are imported lazily so this module can
be loaded (and the pure-Python helpers used) before the JVM is up.
"""

from __future__ import annotations

import typing

import claripy
import z3


def _z3_backend():
    return claripy.backends.z3


_SYMZ3_UF_PREFIX = "load_"


def _matching_subterms(
    expr: "z3.ExprRef", match: typing.Callable[["z3.ExprRef"], bool]
) -> list:
    """The distinct applications in ``expr`` that ``match`` accepts, in
    depth-first order, without looking inside the ones it accepts.

    SymZ3 shares subterms heavily (each flag reuses the same sum), so visit
    each node once; walking the expression as a tree is exponential.
    """
    found: list = []
    seen: set = set()
    stack = [expr]
    while stack:
        node = stack.pop()
        if node.get_id() in seen:
            continue
        seen.add(node.get_id())
        if z3.is_app(node) and match(node):
            found.append(node)
            continue
        stack.extend(reversed(node.children()))
    return found


def _substitute_symz3_load_ufs(expr: "z3.ExprRef") -> "z3.ExprRef":
    """Replace SymZ3 ``load_*_*`` UF applications with fresh ``z3.BitVec`` leaves.

    Each unique UF call (by structural AST identity) maps to one placeholder;
    the placeholder bitvector has the same sort as the UF's result. Equivalent
    repeated calls within a single expression therefore share a leaf, which
    preserves claripy-level equality on round-trip.
    """
    pairs: list = []
    for node in _matching_subterms(
        expr,
        lambda node: node.decl().kind() == z3.Z3_OP_UNINTERPRETED
        and node.decl().name().startswith(_SYMZ3_UF_PREFIX),
    ):
        placeholder = z3.BitVec(
            f"_symz3_{node.decl().name()}_{len(pairs)}", node.sort().size()
        )
        pairs.append((node, placeholder))
    if not pairs:
        return expr
    return z3.substitute(expr, *pairs)


def _rewrite_implies(expr: "z3.ExprRef") -> "z3.ExprRef":
    """Rewrite ``(=> a b)`` as ``(or (not a) b)``.

    Claripy's z3 backend has no entry for implication, which Ghidra's SymZ3
    uses in, for one, ARM's carry and overflow flags.
    """
    # SymZ3 shares subterms heavily (each flag reuses the same sum), so
    # rebuild each node once, children first, rather than walking a tree.
    rebuilt: dict = {}
    stack = [expr]
    while stack:
        node = stack[-1]
        if node.get_id() in rebuilt:
            stack.pop()
            continue
        children = node.children() if z3.is_app(node) else []
        pending = [child for child in children if child.get_id() not in rebuilt]
        if pending:
            stack.extend(pending)
            continue
        stack.pop()
        args = [rebuilt[child.get_id()] for child in children]
        result = node
        if z3.is_app(node) and node.decl().kind() == z3.Z3_OP_IMPLIES:
            result = z3.Or(z3.Not(args[0]), args[1])
        elif any(not arg.eq(child) for arg, child in zip(args, children)):
            result = node.decl()(*args)
        rebuilt[node.get_id()] = result
    return rebuilt[expr.get_id()]


def _for_claripy(expr: "z3.ExprRef") -> "z3.ExprRef":
    """Rewrite what claripy's z3 backend can't abstract."""
    return _rewrite_implies(_substitute_symz3_load_ufs(expr))


def claripy_bool_to_smt2(expr: claripy.ast.bool.Bool) -> str:
    """Serialize a claripy boolean expression to a self-contained SMT-LIB2
    benchmark string (includes ``(declare-fun ...)`` for every free symbol)."""
    z3expr = _z3_backend().convert(expr)
    solver = z3.Solver()
    solver.add(z3expr)
    return solver.to_smt2()


def claripy_bv_to_smt2(bv: claripy.ast.bv.BV) -> str:
    """Serialize a claripy bitvector to a SymZ3-compatible 'V:'-prefixed string.

    SymZ3's ``SymValueZ3.serialize(ctx, BitVecExpr)`` wraps the value as the
    assertion ``(= bv bv)`` so the SMT-LIB parser can ingest it. We mirror that
    convention exactly so a Java-side parse can unwrap to a ``BitVecExpr``.
    """
    z3expr = _z3_backend().convert(bv)
    solver = z3.Solver()
    solver.add(z3expr == z3expr)
    return "V:" + solver.to_smt2()


def smt2_to_claripy_bool(smt: str) -> claripy.ast.bool.Bool:
    """Parse an SMT-LIB2 assertion (the first one) into a claripy boolean."""
    if smt.startswith("B:"):
        smt = smt[2:]
    assertions = z3.parse_smt2_string(smt)
    if len(assertions) == 0:
        raise ValueError(f"No assertions found in SMT-LIB string: {smt[:80]}...")
    return _z3_backend()._abstract(_for_claripy(assertions[0]))


def smt2_to_claripy_bv(smt: str) -> claripy.ast.bv.BV:
    """Parse a SymZ3 'V:'-prefixed SMT-LIB string into a claripy bitvector.

    The wrapper assertion is ``(= bv bv)``; we unwrap by taking the first
    argument of the equality.
    """
    if smt.startswith("V:"):
        smt = smt[2:]
    assertions = z3.parse_smt2_string(smt)
    if len(assertions) == 0:
        raise ValueError(f"No assertions found in SMT-LIB string: {smt[:80]}...")
    children = assertions[0].children()
    if len(children) == 0:
        raise ValueError(f"SMT-LIB BV wrapper assertion has no children: {smt[:80]}...")
    return _z3_backend()._abstract(_for_claripy(children[0]))


def claripy_to_java_bv(jctx, bv: claripy.ast.bv.BV):
    """Translate a claripy bitvector into a Java Z3 ``BitVecExpr`` bound to ``jctx``.

    Requires an active JVM (raises if JPype has not been initialized).
    """
    smt = claripy_bv_to_smt2(bv)
    payload = smt[2:] if smt.startswith("V:") else smt
    parsed = jctx.parseSMTLIB2String(payload, None, None, None, None)
    return parsed[0].getArgs()[0]
