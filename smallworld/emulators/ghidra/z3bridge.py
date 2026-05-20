"""SMT-LIB bridge between claripy and Ghidra's Java Z3.

Both sides ultimately use Microsoft Z3, but each has its own AST representation:
a Python ``z3``/claripy AST on the Python side, and a ``com.microsoft.z3.Context``
on the JVM side. We exchange expressions as SMT-LIB2 strings so neither side
holds a reference to the other's native object.

The Java-side helpers expect a ``jctx`` (``com.microsoft.z3.Context``) and
return JPype-wrapped Java types. They are imported lazily so this module can
be loaded (and the pure-Python helpers used) before the JVM is up.
"""

from __future__ import annotations

import claripy
import z3


def _z3_backend():
    return claripy.backends.z3


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
    return _z3_backend()._abstract(assertions[0])


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
        raise ValueError(
            f"SMT-LIB BV wrapper assertion has no children: {smt[:80]}..."
        )
    return _z3_backend()._abstract(children[0])


def claripy_to_java_bv(jctx, bv: claripy.ast.bv.BV):
    """Translate a claripy bitvector into a Java Z3 ``BitVecExpr`` bound to ``jctx``.

    Requires an active JVM (raises if JPype has not been initialized).
    """
    smt = claripy_bv_to_smt2(bv)
    payload = smt[2:] if smt.startswith("V:") else smt
    parsed = jctx.parseSMTLIB2String(payload, None, None, None, None)
    return parsed[0].getArgs()[0]
