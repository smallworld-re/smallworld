import angr


class SyscallHookProcedure(angr.SimProcedure):
    def run(self):
        # Get the syscall number
        number = self.cc.syscall_num(self.state)

        if number.symbolic:
            raise NotImplementedError(f"Symbolic syscall number {number}")
        number = number.concrete_value

        # See if we have a global handler
        global_func = self.state.scratch.global_syscall_func
        if global_func is not None:
            global_func(self.state, number)

        # See if we have a local handler
        if number in self.state.scratch.syscall_funcs:
            local_func = self.state.scratch.syscall_funcs[number]
            local_func(self.state)

        # Force execution to resume at the syscall exit point.
        self.jump(self.state._ip)


class HookableSimOS(angr.simos.simos.SimOS):
    def syscall(self, state, allow_unsupported=True):
        SYSCALL_CC = angr.calling_conventions.SYSCALL_CC
        arch_name = state.arch.name
        os_name = state.os_name
        if arch_name in SYSCALL_CC:
            if os_name in SYSCALL_CC[arch_name]:
                cc = SYSCALL_CC[arch_name][os_name](state.arch)
            else:
                cc = SYSCALL_CC[arch_name]["default"](state.arch)
        else:
            cc = None

        out = SyscallHookProcedure(
            project=self.project,
            cc=cc,
            prototype=None,
            returns=None,
            is_syscall=True,
            is_stub=False,
            num_args=None,
            display_name=None,
            library_name=None,
            is_function=None,
        )
        out.addr = state._ip
        return out
