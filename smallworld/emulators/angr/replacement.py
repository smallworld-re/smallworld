"""A hardened replacement solver for angr.

angr's stock ``claripy.SolverReplacement`` runs ``claripy.replace_dict`` over
every constraint on each ``add()``.  That walk descends into every node of the
expression and only memoizes a subtree when a replacement actually fires, so on
deeply-shared symbolic expressions -- a loop over a register or uninitialized
value, say -- it re-expands shared subtrees and its cost is exponential in the
sharing depth.  Registers (bound with constraints) and ``SYMBOL_FILL`` values
are never replacements, so even an analysis that only labels *memory* is exposed
whenever a branch guard is built from those.

``MemoizingReplacementSolver`` closes that path with two changes to
``_replacement``:

1. **Disjoint short-circuit.**  If a constraint shares no variables with any
   registered replacement, there is nothing to substitute -- return it
   untouched, in O(1), without walking it at all.  This alone handles the common
   case (guards that touch no labeled memory).

2. **Full memoization.**  When a walk is unavoidable (a guard mixes labeled
   memory with deeply-shared unlabeled subterms), substitute with a per-call
   memo that caches *every* node -- identity results included -- so each distinct
   node is visited once.  That makes the walk linear in the number of distinct
   nodes instead of exponential.

Results are identical to the stock frontend; only the traversal cost changes.
"""

from __future__ import annotations

import typing

import claripy
from claripy.solvers import SolverReplacement


class MemoizingReplacementSolver(SolverReplacement):
    """A ``SolverReplacement`` whose replacement walk is linear, not exponential.

    See the module docstring for the rationale.  Drop-in for
    ``claripy.SolverReplacement``.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Names of every variable that has a replacement registered.  Lets us
        # skip the walk entirely for constraints that touch none of them.
        self._replaced_var_names: typing.Set[str] = set()

    # -- keep _replaced_var_names in sync across registration and branching --

    def add_replacement(self, old, new, **kwargs):
        if isinstance(old, claripy.ast.Base):
            self._replaced_var_names |= old.variables
        return super().add_replacement(old, new, **kwargs)

    def clear_replacements(self):
        super().clear_replacements()
        self._replaced_var_names = set()

    def _blank_copy(self, c):
        super()._blank_copy(c)
        c._replaced_var_names = set()

    def _copy(self, c):
        super()._copy(c)
        c._replaced_var_names = set(self._replaced_var_names)

    # -- the hardened replacement --

    def _replacement(self, old):
        if not isinstance(old, claripy.ast.Base):
            return old

        # (1) Nothing to replace in here: skip the walk.
        if old.variables.isdisjoint(self._replaced_var_names):
            return old

        cached = self._replacement_cache.get(old.hash())
        if cached is not None:
            return cached

        # (2) Fully-memoized substitution (linear in distinct nodes).
        new = self._memoized_replace(old)
        if new is not old:
            self._replacement_cache[old.hash()] = new
        return new

    def _memoized_replace(self, expr: claripy.ast.Base) -> claripy.ast.Base:
        replacements = self._replacement_cache
        memo: typing.Dict[int, typing.Any] = {}
        # Iterative post-order DFS.  `out` accumulates finished results in
        # completion order; children land immediately before their parent.
        stack: typing.List[typing.Tuple[typing.Any, bool]] = [(expr, False)]
        out: typing.List[typing.Any] = []
        while stack:
            node, processed = stack.pop()

            if not isinstance(node, claripy.ast.Base):
                out.append(node)
                continue

            h = node.hash()
            if not processed:
                memoed = memo.get(h)
                if memoed is not None:
                    out.append(memoed)
                    continue
                if h in replacements:
                    memo[h] = replacements[h]
                    out.append(replacements[h])
                    continue
                if node.is_leaf() or not node.args:
                    memo[h] = node
                    out.append(node)
                    continue
                # Descend: reprocess this node after its children finish.
                stack.append((node, True))
                for arg in reversed(node.args):
                    stack.append((arg, False))
                continue

            # Second visit: children results are the last len(args) of `out`.
            n = len(node.args)
            new_args = out[-n:]
            del out[-n:]
            if any(a is not b for a, b in zip(node.args, new_args)):
                res = node.make_like(node.op, tuple(new_args))
            else:
                res = node
            memo[h] = res
            out.append(res)

        assert len(out) == 1, ("replacement walk left a malformed stack", len(out))
        return out[0]
