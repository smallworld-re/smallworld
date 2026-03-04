import copy

import angr

from ...utils import RangeCollection


class ExpandedScratchPlugin(angr.state_plugins.SimStateScratch):
    # A lot of SmallWorld configuration is state-dependent.
    # The correct place to track this is on the scratch plugin.
    #
    # This also includes a handy analysis update.
    # angr uses scratch to store the current guard condition,
    # which is extremely useful for tracking execution.
    # This plugin hooks that feature,
    # and stores a history of guard conditions.
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
        self._guard = None
        self.guards = []

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
            self.guards.extend(scratch.guards)
            for name, ext in scratch.extensions.items():
                self.extensions[name] = copy.deepcopy(ext)

    @property
    def guard(self):
        return self._guard

    @guard.setter
    def guard(self, expr):
        # When angr tries to set the 'guard' attribute,
        # hook the operation and add the guard to the history.
        #
        # This is a bit tricky, since angr sets 'guard' several times
        # when processing a given state.
        #
        # TODO: Need to test; I'm not sure it will capture single-block loops correctly.
        self._guard = expr
        if self.state is not None and not self.state._ip.symbolic:
            out = (self.state._ip.concrete_value, expr)
            if len(self.guards) == 0:
                self.guards.append(out)
            elif self.guards[-1][0] != out[0]:
                self.guards.append(out)
            else:
                self.guards[-1] = out

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return self.__class__(scratch=self)
