import angr

from ...utils import RangeCollection


class ExpandedScratchPlugin(angr.state_plugins.SimStateScratch):
    def __init__(self, scratch=None):
        super().__init__(scratch=scratch)
        self.exitpoints = set()
        self.bounds = RangeCollection()
        self.memory_map = RangeCollection()
        self.global_insn_bp = None
        self.global_read_bp = None
        self.global_write_bp = None
        self.insn_bps = dict()
        self.func_bps = dict()
        self.mem_read_bps = dict()
        self.mem_write_bps = dict()

        if scratch is not None:
            self.exitpoints |= scratch.exitpoints
            self.bounds.update(scratch.bounds)
            self.memory_map.update(scratch.memory_map)
            self.global_insn_bp = scratch.global_insn_bp
            self.global_read_bp = scratch.global_read_bp
            self.global_write_bp = scratch.global_write_bp
            self.insn_bps.update(scratch.insn_bps)
            self.func_bps.update(scratch.func_bps)
            self.mem_read_bps.update(scratch.mem_read_bps)
            self.mem_write_bps.update(scratch.mem_write_bps)

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return self.__class__(scratch=self)
