import angr


class ExpandedScratchPlugin(angr.state_plugins.SimStateScratch):
    def __init__(self, scratch=None):
        super().__init__(scratch=scratch)
        self.bounds = []

        if scratch is not None:
            self.bounds.extend(scratch.bounds)

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return ExpandedScratchPlugin(scratch=self)
