import angr


class ExpandedScratchPlugin(angr.state_plugins.SimStateScratch):
    def __init__(self, scratch=None):
        super().__init__(scratch=scratch)
        self.bounds = list()
        self.insn_bps = dict()
        self.mem_read_bps = dict()
        self.mem_write_bps = dict()

        if scratch is not None:
            self.bounds.extend(scratch.bounds)
            self.insn_bps.update(scratch.insn_bps)
            self.mem_read_bps.update(scratch.mem_read_bps)
            self.mem_write_bps.update(scratch.mem_write_bps)

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return self.__class__(scratch=self)
