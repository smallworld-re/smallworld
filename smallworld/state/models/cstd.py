import abc

from ... import emulators
from .model import Model


class CStdModel(Model):
    """Base class for C standard function models


    Regardless of which version of a library you use,
    all "true" C functions will use the same interface
    defined by the ABI.
    (There are exceptions, such as thunks and internal functions
    never intended for human eyes)

    This abstracts away the ABI-specific operations
    performed by a function, namely getting args and returning vals.
    """

    @abc.abstractmethod
    def get_arg1(self, emulator: emulators.Emulator) -> int:
        raise NotImplementedError()

    @abc.abstractmethod
    def get_arg2(self, emulator: emulators.Emulator) -> int:
        raise NotImplementedError()

    @abc.abstractmethod
    def get_arg3(self, emulator: emulators.Emulator) -> int:
        raise NotImplementedError()

    @abc.abstractmethod
    def get_arg4(self, emulator: emulators.Emulator) -> int:
        raise NotImplementedError()

    @abc.abstractmethod
    def get_arg5(self, emulator: emulators.Emulator) -> int:
        raise NotImplementedError()

    @abc.abstractmethod
    def get_arg6(self, emulator: emulators.Emulator) -> int:
        raise NotImplementedError()

    @abc.abstractmethod
    def set_return_value(self, emulator: emulators.Emulator, val: int) -> None:
        raise NotImplementedError()
