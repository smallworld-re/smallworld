import angr


class SyscallHookProcedure(angr.SimProcedure):
    def run(self):
        # Get the syscall number
        if hasattr(self.state.arch, "syscall_num_offset"):
            off = self.state.arch.syscall_num_offset
        elif self.state.arch.name == "MIPS64":
            # Of _COURSE_ mips64 is the exception.
            # It's v0, like mips32, but angr doesn't code this correctly.
            off = 32
        else:
            raise NotImplementedError(
                f"Syscalls not supported for {self.state.arch.name}"
            )

        size = self.state.arch.bytes
        number = self.state.registers.load(off, size)
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
        out = SyscallHookProcedure(
            project=self.project,
            cc=None,
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
