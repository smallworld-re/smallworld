import logging

from angr.factory import AngrObjectFactory

from ...exceptions import AnalysisError

log = logging.getLogger(__name__)


class PatchedObjectFactory(AngrObjectFactory):
    """Extension of AngrObjectFactory to allow function overrides

    There are a couple of core functions (blocks)
    which need to get overloaded, but which are not exposed
    to any kind of plugin interface.
    """

    def block(self, *args, **kwargs):
        if "backup_state" in kwargs:
            # Bound block lifting based on our code bounds
            # Angr's Vex lifter will happily run off the edge of memory,
            # interpreting undefined memory as zeroes.
            state = kwargs["backup_state"]
            bound = None
            if state._ip.symbolic:
                raise AnalysisError("Cannot build a block for a symbolic IP")
            ip = state._ip.concrete_value
            for b in state.scratch.bounds:
                if ip in b:
                    bound = b
            if b is None:
                raise AnalysisError("ip 0x{ip:x} is out of bounds")
            max_size = bound.stop - ip
            max_size = min(max_size, 4096)
            kwargs["size"] = max_size

        return super().block(*args, **kwargs)
