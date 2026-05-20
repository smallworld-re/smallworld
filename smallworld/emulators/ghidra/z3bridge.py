"""SMT-LIB bridge between claripy and Ghidra's Java Z3.

Both sides ultimately use Microsoft Z3, but they live in different processes-
in-the-same-process: a Python ``z3``/claripy AST and a JVM
``com.microsoft.z3.Context``. We exchange expressions as SMT-LIB2 strings so
neither side holds a reference to the other's AST.

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
    equality = assertions[0]
    children = equality.children()
    if len(children) == 0:
        raise ValueError(
            f"SMT-LIB BV wrapper assertion has no children: {smt[:80]}..."
        )
    return _z3_backend()._abstract(children[0])


# --- Java-side helpers (lazy import; require an active JVM) ---


def _SymValueZ3_class():
    import jpype  # noqa: F401  (forces a clear error if JVM not up)

    import jpype

    return jpype.JClass("ghidra.symz3.model.SymValueZ3")


def claripy_to_java_bool(jctx, expr: claripy.ast.bool.Bool):
    """Translate a claripy boolean into a Java Z3 ``BoolExpr`` bound to ``jctx``."""
    smt = claripy_bool_to_smt2(expr)
    parsed = jctx.parseSMTLIB2String(smt, None, None, None, None)
    return parsed[0]


def claripy_to_java_bv(jctx, bv: claripy.ast.bv.BV):
    """Translate a claripy bitvector into a Java Z3 ``BitVecExpr`` bound to ``jctx``."""
    smt = claripy_bv_to_smt2(bv)
    # Strip the "V:" decoration we added; parseSMTLIB2String wants pure SMT-LIB.
    payload = smt[2:] if smt.startswith("V:") else smt
    parsed = jctx.parseSMTLIB2String(payload, None, None, None, None)
    equality = parsed[0]
    return equality.getArgs()[0]


def java_bool_to_claripy(jctx, jbool) -> claripy.ast.bool.Bool:
    """Read a Java Z3 ``BoolExpr`` back into claripy via SMT-LIB."""
    smt = _SymValueZ3_class().serialize(jctx, jbool)
    return smt2_to_claripy_bool(str(smt))


def java_bv_to_claripy(jctx, jbv) -> claripy.ast.bv.BV:
    """Read a Java Z3 ``BitVecExpr`` back into claripy via SMT-LIB."""
    smt = _SymValueZ3_class().serialize(jctx, jbv)
    return smt2_to_claripy_bv(str(smt))


def claripy_to_sym_value(jctx, value: typing.Union[int, claripy.ast.bv.BV], size_bits: int):
    """Build a Java ``SymValueZ3`` from a claripy BV or Python int.

    Used when writing to Ghidra's symbolic state piece.
    """
    SymValueZ3 = _SymValueZ3_class()
    if isinstance(value, claripy.ast.bv.BV):
        jbv = claripy_to_java_bv(jctx, value)
    elif isinstance(value, int):
        jbv = jctx.mkBV(value, size_bits)
    else:
        raise TypeError(f"Cannot convert {type(value).__name__} to SymValueZ3")
    return SymValueZ3(jctx, jbv)
