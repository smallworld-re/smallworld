from ...emulators.angr.scratch import ExpandedScratchPlugin


class GuardTrackingScratchPlugin(ExpandedScratchPlugin):
    def __init__(self, scratch=None):
        self._guard = None
        self.guards = []
        super().__init__(scratch=scratch)
        if scratch is not None:
            self.guards.extend(scratch.guards)

    @property
    def guard(self):
        return self._guard

    @guard.setter
    def guard(self, expr):
        self._guard = expr
        if self.state is not None:
            out = (self.state._ip.concrete_value, expr)
            if len(self.guards) == 0:
                self.guards.append(out)
            elif self.guards[-1][0] != out[0]:
                self.guards.append(out)
            else:
                self.guards[-1] = out
