import claripy
from angr.concretization_strategies import SimConcretizationStrategy
from angr.errors import SimUnsatError, SimValueError

from ...exceptions import AnalysisError


class UnboundAddressError(AnalysisError):
    def __init__(self, msg: str, address: claripy.ast.bv.BV, is_read: bool, *args):
        super().__init__(msg)
        self.address = address
        self.is_read = is_read


class SimConcretizationStrategyFault(SimConcretizationStrategy):
    def __init__(self, is_read: bool, **kwargs):
        super().__init__(**kwargs)
        self.is_read = is_read

    def _concretize(self, memory, addr, **kwargs):
        try:
            return [memory.state.solver.eval_one(addr)]
        except SimValueError:
            raise UnboundAddressError(
                f"Tried to concretize unbound expression {addr}", addr, self.is_read
            )
        except SimUnsatError:
            raise NotImplementedError(f"Tried to concretize unsat {addr}")
