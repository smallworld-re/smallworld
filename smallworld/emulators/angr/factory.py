import logging

from angr.errors import SimValueError
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
            addr = args[0] if args else kwargs.get("addr")
            if addr is not None:
                # The block asked for, which need not be at the state's pc.
                ip = addr
            else:
                try:
                    ip = state.solver.eval_one(state._ip)
                except SimValueError:
                    raise AnalysisError("Cannot step an unconstrained state")
            if kwargs.get("thumb") or (
                ip & 1 and self.project.arch.name.startswith("ARM")
            ):
                # angr addresses ARM Thumb code with the Thumb bit set;
                # measure the block from the instruction's real address.
                ip &= ~1

            # Check if the ip is mapped
            r, found = state.scratch.memory_map.find_closest_range(ip)
            if not found:
                # Nope.  No code here.
                log.warn(f"No block mapped at {state._ip}")
                max_size = 0
            else:
                # Yep.  We have an upper bound on our block
                start, stop = r
                max_size = stop - ip
                if not state.scratch.bounds.is_empty():
                    # We also have bounds.  Test if we're in those
                    r, found = state.scratch.bounds.find_closest_range(ip)
                    if not found:
                        # Nope.  Out of bounds.
                        log.warn(f"{state._ip} is out of bounds")
                        max_size = 0
                    else:
                        # Yep.  Allow anything in bounds and in memory
                        start, stop = r
                        max_size = min(max_size, stop - ip)

                for exit_point in state.scratch.exit_points:
                    if exit_point >= ip and exit_point < ip + max_size:
                        max_size = exit_point - ip

            if max_size == 0:
                log.warn(f"Empty block at {state._ip}")
            max_size = min(max_size, 4096)
            kwargs["size"] = max_size

        return super().block(*args, **kwargs)
