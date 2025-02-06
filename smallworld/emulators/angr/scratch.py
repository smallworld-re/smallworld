import copy

import angr

from ...utils import RangeCollection


class ExpandedScratchPlugin(angr.state_plugins.SimStateScratch):
    def __init__(self, scratch=None):
        super().__init__(scratch=scratch)
        self.exit_points = set()
        self.bounds = RangeCollection()
        self.memory_map = RangeCollection()
        self.global_insn_bp = None
        self.global_syscall_func = None
        self.global_read_bp = None
        self.global_write_bp = None
        self.insn_bps = dict()
        self.func_bps = dict()
        self.syscall_funcs = dict()
        self.mem_read_bps = dict()
        self.mem_write_bps = dict()
        self.extensions = dict()

        if scratch is not None:
            self.exit_points |= scratch.exit_points
            self.bounds.update(scratch.bounds)
            self.memory_map.update(scratch.memory_map)
            self.global_insn_bp = scratch.global_insn_bp
            self.global_syscall_func = scratch.global_syscall_func
            self.global_read_bp = scratch.global_read_bp
            self.global_write_bp = scratch.global_write_bp
            self.insn_bps.update(scratch.insn_bps)
            self.func_bps.update(scratch.func_bps)
            self.syscall_funcs.update(scratch.syscall_funcs)
            self.mem_read_bps.update(scratch.mem_read_bps)
            self.mem_write_bps.update(scratch.mem_write_bps)
            for name, ext in scratch.extensions.items():
                self.extensions[name] = copy.deepcopy(ext)

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return self.__class__(scratch=self)
