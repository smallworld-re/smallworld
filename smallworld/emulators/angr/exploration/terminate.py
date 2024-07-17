from ..exceptions import PathTerminationSignal


class TerminationExplorationMixin:
    """
    Mixin allowing analyses to terminate a single path.

    This allows analyses to raise an exception
    that aborts successor computation cleanly,
    rather than producing an 'error' state.

    NOTE: To be effective, this needs to be at the top
    of the mixin hierarchy
    """

    def step_state(self, simgr, state, **kwargs):
        try:
            out = super().step_state(simgr, state, **kwargs)
        except PathTerminationSignal:
            out = dict()

        return out
