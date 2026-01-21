class AbstractAngrEmulator(
    Emulator,
    InstructionHookable,
    FunctionHookable,
    SyscallHookable,
    MemoryReadHookable,
    MemoryWriteHookable,
    ConstrainedEmulator,
):
