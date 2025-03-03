import logging

import claripy
from angr.errors import SimMemoryAddressError
from angr.storage.memory_mixins.memory_mixin import MemoryMixin

from ...exceptions import AnalysisSignal
from ...hinting import UnderSpecifiedMemoryBranchHint, get_hinter

log = logging.getLogger(__name__)
hinter = get_hinter(__name__)


class ConditionalDereferenceSignal(AnalysisSignal):
    """Fault for communicating divergent address data between plugins.

    Condtional address concretizations are detected
    in the memory plugin, but can only be resolved
    in the exploration strategy.
    """

    def __init__(self, state, addr, results):
        self.state = state
        self.addr = addr
        self.results = results


class ConcretizationMemoryMixin(MemoryMixin):
    """Mixin for concretizing conditional expressions.

    By default, angr concretizes a conditional expression into a single value.
    This causes a number of potential problems:

    - No one sub-expression receives the binding.
      If a sub-expression is seen elsewhere,
      the solver tends to assume it wasn't the one that got concretize.
    - There isn't a

    This version detects when this will be a problem.
    """

    def _concretize_addr(self, supercall, addr, strategies=None, condition=None):
        guards = dict()
        exprs = dict()
        res = set()
        try:
            # Split the address into non-conditional sub-expressions
            for guard, expr in claripy.ite_cases(addr):
                try:
                    # Concretize the sub-expression normally
                    for tmp in supercall(
                        expr, strategies=strategies, condition=condition
                    ):
                        # Only accept concretizations that satisfy the current state
                        if self.state.satisfiable(extra_constraints=[addr == tmp]):
                            guards[expr] = guard
                            exprs[expr] = tmp
                            res.add(tmp)
                except SimMemoryAddressError as e:
                    # Something went wrong that shouldn't have gone wrong
                    log.error(
                        f"Could not concretize expression {expr} with following constraints:"
                    )
                    for expr in self.state.solver.constraints:
                        log.error(f"\t{expr}")
                    log.exception("Cause:")
                    raise e
        except AnalysisSignal as s:
            # A lower analysis raised a signal.
            # Raise it upward.
            raise s
        except Exception as e:
            # Something went wrong that shouldn't go wrong.
            log.exception(f"Fatal error concretizing {addr}")
            raise e

        if len(exprs) > 1:
            # We're trying to dereference a conditional address
            hint = UnderSpecifiedMemoryBranchHint(
                message="Conditional address dereference",
                instruction=self.state._ip.concrete_value,
                address=str(addr),
                options=[(str(k), str(v)) for (k, v) in guards.items()],
            )
            hinter.info(hint)
            # We can't modify successors here;
            # we need to punt upward to the exploration strategy
            raise ConditionalDereferenceSignal(self.state, addr, exprs)

        return list(res)

    def concretize_read_addr(self, addr, strategies=None, condition=None):
        return self._concretize_addr(
            super().concretize_read_addr, addr, strategies, condition
        )

    def concretize_write_addr(self, addr, strategies=None, condition=None):
        return self._concretize_addr(
            super().concretize_write_addr, addr, strategies, condition
        )


class ConcretizationExplorationMixin:
    def step_state(self, simgr, state, **kwargs):
        try:
            out = super().step_state(simgr, state, **kwargs)
        except ConditionalDereferenceSignal as e:
            # Fault: we got a conditional address.
            #
            # This means that we tried to dereference a
            # conditional symbolic expression.
            # Normal address concretization causes a big loss of precision;
            # binding a conditional expression doesn't clearly bind any
            # one symbol.
            #
            # One way to handle this is to fork the state,
            # with one state per possible evaluation of the
            # conditional expression.
            #
            # The possible values and their concretizations
            # are computed in the memory plugin,
            # but it's not possible to fork a state in that plugin.
            # It sends us its results via a CondtionalAddressException,
            # and we fix it up here.

            # Set up the successors dict
            out = {None: list(), "unsat": list()}

            # Bind all address concretizations
            backup = e.state.copy()
            for expr, addr in e.results.items():
                backup.solver.add(expr == addr)

            # Fork a new state for each possible
            # binding of the conditional address
            for expr, addr in e.results.items():
                new_state = backup.copy()
                new_state.solver.add(e.addr == addr)

                # Test the new state for satisfiability.
                # This really should never be a problem,
                # but sometimes the concretizer gets things wrong
                if new_state.solver.satisfiable():
                    out[None].append(new_state)
                else:
                    out["unsat"].append(new_state)
        return out
