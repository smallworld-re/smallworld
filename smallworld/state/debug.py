import code
import logging

from .. import emulators, initializers
from . import state

logger = logging.getLogger(__name__)


class Breakpoint(state.Value):
    """An interactive breakpoint.

    Stops execution at the specified address and opens an interactive shell.

    Arguments:
        address: The address of the breakpoint.
    """

    def __init__(self, address: int):
        self.address = address

    @property
    def value(self):
        raise NotImplementedError()

    @value.setter
    def value(self, value) -> None:
        raise NotImplementedError()

    def initialize(
        self, initializer: initializers.Initializer, override: bool = False
    ) -> None:
        logger.debug(f"skipping initialization for {self} (hook)")

    def load(self, emulator: emulators.Emulator, override: bool = True) -> None:
        logger.debug(f"{self} loading not supported - load skipped")

    def apply(self, emulator: emulators.Emulator) -> None:
        def interact(emulator: emulators.Emulator) -> None:
            code.interact(
                banner=f"breakpoint at 0x{self.address:x} - interactive mode...",
                local={"emulator": emulator},
                exitmsg="continuing...",
            )

        emulator.hook(self.address, interact)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(0x{self.address:x})"


__all__ = ["Breakpoint"]
