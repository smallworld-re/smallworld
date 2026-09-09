from ...emulators.angr.scratch import ExpandedScratchPlugin


class GuardTrackingScratchPlugin(ExpandedScratchPlugin):
    def __init__(self, scratch=None):
        self._guard = None
        self.guards = []
        # The parent __init__ already copies scratch.guards when scratch is
        # not None; extending again here duplicated the entire guard history
        # on every state fork.
        super().__init__(scratch=scratch)

    @property
    def guard(self):
        return self._guard

    @guard.setter
    def guard(self, expr):
        self._guard = expr
        # angr sets `guard` while the instruction pointer can still be
        # symbolic; reading concrete_value then raises. Mirror the parent and
        # only record the guard once the IP is concrete.
        if self.state is not None and not self.state._ip.symbolic:
            out = (self.state._ip.concrete_value, expr)
            if len(self.guards) == 0:
                self.guards.append(out)
            elif self.guards[-1][0] != out[0]:
                self.guards.append(out)
            else:
                self.guards[-1] = out
