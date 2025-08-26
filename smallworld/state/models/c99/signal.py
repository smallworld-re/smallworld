import typing

from .... import emulators
from ..cstd import ArgumentType, CStdModel

# NOTE: Most of signal.h is not defined in C99
#
# If you're familiar with Linux,
# the rest of the functions you're looking for
# are part of the POSIX standard.
#
# Windows only implements the C99 API;
# I suspect it keeps most process lifecycle controls
# internal to its own application runtimes.


class Raise(CStdModel):
    name = "raise"

    # int raise(int sig);
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    # Most of our emulators can't model signals.
    # I'm not sure it's possible to model raising one.
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # Not really modeled; just return success
        self.set_return_value(emulator, 0)


class Signal(CStdModel):
    name = "signal"

    # typedef void (*sighandler_t)(int);
    # sighandler_t signal(int sig, sighandler_t func);
    argument_types = [ArgumentType.INT, ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    # Most of our emulators can't model signals.
    imprecise = True

    def __init__(self, address: int):
        super().__init__(address)
        # Track any registered handlers.
        # Sometimes programs care about this.
        self.handlers: typing.Dict[int, int] = dict()

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        sig = self.get_arg1(emulator)
        func = self.get_arg2(emulator)

        assert isinstance(sig, int)
        assert isinstance(func, int)

        # Get the old handler.  Default to SIG_DFL, or NULL.
        old_func = self.handlers.get(sig, 0)
        self.handlers[sig] = func

        self.set_return_value(emulator, old_func)


__all__ = [
    "Raise",
    "Signal",
]
