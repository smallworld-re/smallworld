import angr
from angr.storage.memory_mixins import MemoryMixin
from .base import BaseMemoryMixin
from .exceptions import AnalysisSignal
from .terminate import PathTerminationSignal
from .visitor import ConditionalVisitor
from .utils import print_state
from ..utils.tui import SimpleTUI, TUIContinueException


class DivergentAddressSignal(AnalysisSignal):
    """
    "Fault" for communicating divergent address data between plugins.

    Divergent address concretizations are detected
    in the memory plugin, but can only be resolved
    in the exploration strategy.
    """

    def __init__(self, state, addr, results):
        self.state = state
        self.addr = addr
        self.results = results


class DivergenceMemoryMixin(BaseMemoryMixin):
    _visitor = ConditionalVisitor()
    """
    Mixin for handling memory-side address concretization
    """

    def _setup_tui(self):
        super()._setup_tui()
        self.divergence_tui = SimpleTUI()
        self.divergence_tui.add_case(
            "fork",
            self.divergence_fork,
            hint="Fork separate states for each possible evaluation",
        )
        self.divergence_tui.add_case(
            "choose", self.divergence_choose, hint="Choose one possible evaluation"
        )
        self.divergence_tui.add_case(
            "ignore",
            self.divergence_ignore,
            hint="Use a conjunction of all possible evaluations",
        )
        self.divergence_tui.add_case(
            "details",
            self.divergence_details,
            hint="Print details of the current state",
        )
        self.divergence_tui.add_case(
            "stop", self.divergence_stop, hint="Stop the current execution path"
        )
        self.divergence_tui.add_case(
            "quit", self.divergence_quit, hint="Exit the analyzer"
        )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @MemoryMixin.memo
    def copy(self, memo):
        o = super().copy(memo)
        o._setup_tui()
        return o

    def _concretize_addr(self, supercall, addr, strategies=None, condition=None):
        """
        Helper function for performing conditional concretization.

        This replaces the normal concretization strategy,
        which is to compute all possible suggestions for addr,
        and to assert the OR of them.

        This default strategy falls over badly for addresses computed
        via conditional data flow, since said addresses will be
        essentially a case-statement of several possible base addresses.
        The resulting assertion becomes "one of these variables stores one of these addresses."
        This loses a lot of precision.

        This implementation works as follows:

        - Carve apart the address expression into all possible non-conditional expressions
        - Concretize each possible expression independently.
        - If there is more than one possible sub-expression, raise an exception.
        - The exception acts as a virtual pagefault, which carries data back to the exploration strategy.
        - The exploration strategy creates one state per sub-expression, constrained so that said expression is picked.

        N.B.: This is in a separate helper because the operation is identical
        for concretizing reads and writes.
        """
        exprs = dict()
        res = set()

        try:
            # Split the address into non-conditional sub-expressions.
            for expr in self._visitor.visit(addr):
                try:
                    # Concretize the sub-expression normally
                    for tmp in supercall(
                        expr, strategies=strategies, condition=condition
                    ):
                        # check that the suggestion is satisfiable.
                        # I'd have hoped that angr does this automatically,
                        # but it doesn't seem to.
                        if self.state.satisfiable(extra_constraints=[addr == tmp]):
                            self.log.debug(
                                f"Concrete result for {expr}, slice of {addr}: {tmp:x}"
                            )
                            # TODO: Handle multiple concretizations from non-conditional source.
                            # I've never actually seen this, but you never know.
                            exprs[expr] = tmp
                            res.add(tmp)
                        else:
                            self.log.debug(
                                f"Ignoring result for {expr}, slice of {addr}: {tmp:x}"
                            )
                            for expr in self.state.solver.constraints:
                                self.log.debug(f"\t{expr}")
                except angr.errors.SimMemoryAddressError as e:
                    # Something went wrong that shouldn't go wrong.
                    self.log.error(
                        f"Could not concretize expression {expr} with following constraints:"
                    )
                    for expr in self.state.solver.constraints:
                        self.log.error(f"\t{expr}")
                    self.log.error(f"Cause: {e}")
                    raise e
        except AnalysisSignal as s:
            # A lower analysis raised a signal.
            # Raise it upwards.
            raise s
        except Exception as e:
            # Something went wrong that shouldn't go wrong.
            self.log.error(f"Fatal error concretizing {addr}")
            self.log.exception(f"Cause: {type(e)} {e}")
            raise e
        self.log.debug(f"All recommendations: {list(map(hex, res))}")
        if len(exprs) > 1:
            # We've got a conditional dereference.
            self.log.warn(f"Conditional address dereferenced at {self.state.ip}.")
            self.log.warn("What do you want to do about this?")
            self.divergence_tui.handle("fork", set(), this=self, addr=addr, exprs=exprs)

        return list(res)

    def concretize_read_addr(self, addr, strategies=None, condition=None):
        self.log.debug(f"Concretizing read addr {addr}")
        return self._concretize_addr(
            super().concretize_read_addr,
            addr,
            strategies=strategies,
            condition=condition,
        )

    def concretize_write_addr(self, addr, strategies=None, condition=None):
        self.log.debug(f"Concretizing write addr {addr}")
        return self._concretize_addr(
            super().concretize_write_addr,
            addr,
            strategies=strategies,
            condition=condition,
        )

    # TUI handler methods.  Fear the boilerplate.
    def divergence_fork(self, addr=None, exprs=None, **kwargs):
        self.log.warn("Rewinding and forking to avoid conditional dereference")
        raise DivergentAddressSignal(self.state, addr, exprs)

    def divergence_choose(**kwargs):
        raise NotImplementedError(
            "Chosing a specific evaluation is not yet implemented"
        )

    def divergence_ignore(self, **kwargs):
        self.log.warn("Accepting conditional dereference")

    def divergence_details(self, addr=None, exprs=None, **kwargs):
        self.log.warn(f"Details of dereference at {self.state.ip}:")
        print_state(self.log.warn, self.state, "conditional dereference")
        self.log.warn(f"Address: {addr}")
        self.log.warn("Possible Evaluations:")
        for expr, result in exprs.items():
            self.log.warn(f"\t{expr}: {result:x}")
        raise TUIContinueException()

    def divergence_stop(self, **kwargs):
        self.log.warn("Killing execution path")
        raise PathTerminationSignal()

    def divergence_quit(self, **kwargs):
        self.log.warn("Aborting execution")
        quit()


class DivergenceExplorationMixin:
    """
    Mixin for handling exploration-side address concretization

    A memory mixin can detect problematic address concretizations,
    but it can't do anything about them beyond modifying
    a single state.

    This exploration strategy mixin allows the memory mixin
    to handle exceptional cases that need to fork a state.
    """

    def step_state(self, simgr, state, **kwargs):
        try:
            out = super().step_state(simgr, state, **kwargs)
            self.log.debug(f"Clean Successors: {state} -> {out}")
            for stash, states in out.items():
                if len(states) > 0:
                    if stash is None:
                        stash = "active"
                    for state in states:
                        self.log.debug(f"\t{state} ({stash}): {state.scratch.guard}")

        except DivergentAddressSignal as e:
            # Fault: we got a divergent address.
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
            # It sends us its results via a DivergentAddressException,
            # and we fix it up here.

            # Set up the successors dict.
            out = {None: list(), "unsat": list()}
            self.log.debug(f"Divergent successors: {state} ->")

            # Bind all address concretizations
            backup = e.state.copy()
            for expr, addr in e.results.items():
                backup.solver.add(expr == addr)

            # Fork a new state for each possible
            # binding of the conditional address.
            for expr, addr in e.results.items():
                new_state = backup.copy()
                new_state.solver.add(e.addr == addr)

                # Test the new state for satisfiability,
                # just in case the concretizer misses something.
                # I wish I didn't have to do this, since it's slow.
                if new_state.solver.satisfiable():
                    self.log.debug(f"\t{new_state} (active): {e.addr == addr}")
                    out[None].append(new_state)
                else:
                    out["unsat"].append(new_state)
                    self.log.debug(f"\t{new_state} (unsat): {e.addr == addr}")
        return out
