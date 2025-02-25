import logging

# import claripy
from angr.storage.memory_mixins.memory_mixin import MemoryMixin

from ....exceptions import AnalysisSignal

log = logging.getLogger(__name__)


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
        try:
            # Split the address
            raise Exception("Derp")
        except AnalysisSignal as s:
            raise s
        except Exception as e:
            log.exception(f"Fatal error concretizing {addr}")
            raise e

    def concretize_read_addr(self, addr, strategies=None, condition=None):
        return self._concretize_addr(
            super().concretize_read_addr, addr, strategies, condition
        )

    def concretize_write_addr(self, addr, strategies=None, condition=None):
        return self._concretize_addr(
            super().concretize_write_addr, addr, strategies, condition
        )
