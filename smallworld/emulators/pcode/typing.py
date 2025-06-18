from ..emulator import (
    Emulator,
    FunctionHookable,
    InstructionHookable,
    MemoryReadHookable,
    MemoryWriteHookable,
)


class AbstractGhidraEmulator(
    Emulator,
    InstructionHookable,
    FunctionHookable,
    MemoryReadHookable,
    MemoryWriteHookable,
):
    """Abstract type for GhidraEmulator

    Normal users of SmallWorld shouldn't need to interact with this class.

    This is for the convenience of the factory function in `__init__.py`.
    The factory needs to annotate its return type with all the
    interfaces supported by GhidraEmulator,
    but it can't use GhidraEmulator in its signature
    because it's not imported until after the first call to the factory.
    """

    pass
