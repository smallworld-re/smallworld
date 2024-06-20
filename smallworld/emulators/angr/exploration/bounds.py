import logging

log = logging.getLogger(__name__)


class BoundedExplorationMixin:
    """
    Mixin forcing execution to obey our code bounds.
    """

    def step_state(self, simgr, state, **kwargs):
        if not state._ip.symbolic:
            ip = state._ip.concrete_value
            bound = None
            for b in state.scratch.bounds:
                if ip in b:
                    bound = b
                    break
            if bound is None:
                return dict()
            kwargs["size"] = bound.stop - ip
        return super().step_state(simgr, state, **kwargs)
