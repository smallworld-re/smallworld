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
            if state._ip.symbolic:
                raise AnalysisError("Cannot build a block for a symbolic IP")
            ip = state._ip.concrete_value

            # Check if the ip is mapped
            (r, found) = state.scratch.memory_map.find_closest_range(ip)
            if not found:
                # Nope.  No code here.
                log.warn(f"No block mapped at {state._ip}")
                max_size = 0
            else:
                # Yep.  We have an upper bound on our block
                (start, stop) = r
                max_size = stop - ip
                if not state.scratch.bounds.is_empty():
                    # We also have bounds.  Test if we're in those
                    (r, found) = state.scratch.bounds.find_closest_range(ip)
                    if not found:
                        # Nope.  Out of bounds.
                        log.warn(f"{state._ip} is out of bounds")
                        max_size = 0
                    else:
                        # Yep.  Allow anything in bounds and in memory
                        (start, stop) = r
                        max_size = min(max_size, stop - ip)

            if max_size == 0:
                log.warn(f"Empty block at {state._ip}")
            max_size = min(max_size, 4096)
            kwargs["size"] = max_size

        return super().block(*args, **kwargs)
