import logging

log = logging.getLogger(__name__)


class BoundedExplorationMixin:
    """
    Mixin forcing execution to obey our code bounds.
    """

    def step_state(self, simgr, state, **kwargs):
        if not state._ip.symbolic:
            ip = state._ip.concrete_value
            (r, found) = state.scratch.memory_map.find_closest_range(ip)
            if not found:
                return dict()
            (_, stop) = r
            size = stop - ip
            if not state.scratch.bounds.is_empty():
                (r, found) = state.scratch.bounds.find_closest_range(ip)
                if not found:
                    return dict()
                (_, stop) = r
                size = min(size, stop - ip)

            kwargs["size"] = size
        return super().step_state(simgr, state, **kwargs)
