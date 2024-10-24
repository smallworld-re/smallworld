import logging

log = logging.getLogger(__name__)


class BoundedExplorationMixin:
    """
    Mixin forcing execution to obey our code bounds.
    """

    def step_state(self, simgr, state, **kwargs):
        if not state._ip.symbolic:
            ip = state._ip.concrete_value
            i = state.scratch.memory_map.find_range(ip)
            if i is None:
                return dict()
            (_, stop) = state.scratch.memory_map.ranges[i]
            size = stop - ip
            if not state.scratch.bounds.is_empty():
                i = state.scratch.bounds.find_range(ip)
                if i is None:
                    return dict()
                (_, stop) = state.scratch.bounds[i]
                size = min(size, stop - ip)
            
            kwargs["size"] = size
        return super().step_state(simgr, state, **kwargs)
