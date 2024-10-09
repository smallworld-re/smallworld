import abc
import logging

from ... import emulators
from .. import state

logger = logging.getLogger(__name__)


class MMIOModel(state.Stateful):
    """A model of a memory-mapped IO device.

    This lets you specify alternate handler routines
    for reads and writes within a range of memory addressess,
    bypassing the emulator's normal memory model.
    As the name suggests, this is useful for modeling
    MMIO devices, where accessing a particular address
    actually accesses a register of a peripheral device.

    The callback routines on_read() and on_write()
    will trigger on any access within the specified range;
    one MMIOModel can handle multiple registers,
    allowing you to model an entire device, or even a set of adjacent devices
    in one object.

    Arguments:
        address: Starting address of the MMIO region
        size: Size of the MMIO region in bytes
    """

    def __init__(self, address: int, size: int):
        self.address = address
        self.size = size

    @abc.abstractmethod
    def on_read(self, emu: emulators.Emulator, addr: int, size: int) -> bytes:
        """Callback handling reads from an MMIO register

        NOTE: Results must be encoded in the emulator's byte order.

        NOTE: Models should be robust to partial reads.
        The Unicorn emulator's MMIO model reads at most 4 bytes at once.
        Larger reads will be broken into multiple operations.

        NOTE: Attempting to access memory in this MMIO range
        inside this handler will produce undefined behavior.

        Arguments:
            emu: The emulator object mediating this operation
            addr: The start address of the read operation
            size: The number of bytes read

        Returns:
            `size` bytes containing the result of the modeled read
        """
        raise NotImplementedError("Abstract method")

    @abc.abstractmethod
    def on_write(
        self, emu: emulators.Emulator, addr: int, size: int, value: bytes
    ) -> None:
        """Callback handling writes to an MMIO register

        NOTE: `value` will be encoded in the emulator's byte order.

        NOTE: Models should be robust to partial writes.
        The Unicorn emulator's MMIO model writes at most 4 bytes at once.
        Larger writes will be broken into multiple operations.

        NOTE: Attempting to access memory in this MMIO range
        inside this handler will produce undefined behavior.

        Arguments:
            emu: The emulator object mediating this operation
            addr: The start address of the write operation
            size: The number of bytes written
            value: The bytes written
        """
        raise NotImplementedError("Abstract method")

    @property
    def value(self):
        raise NotImplementedError("MMIO models don't have a value")

    @value.setter
    def value(self, value) -> None:
        raise NotImplementedError("MMIO models don't have a value")

    def extract(self, emulator: emulators.Emulator) -> None:
        logger.debug(f"Skipping extract for {self} (mmio)")

    def apply(self, emulator: emulators.Emulator) -> None:
        logger.warn(f"Hooking MMIO {self} {self.address:x}")
        emulator.map_memory(self.size, self.address)
        if self.on_read is not None:
            if not isinstance(emulator, emulators.MemoryReadHookable):
                raise NotImplementedError("Emulator does not support read hooking")
            logger.info(f"Adding read callback {self.on_read}")
            emulator.hook_memory_read(self.address, self.address + self.size, self.on_read)
        if self.on_write is not None:
            if not isinstance(emulator, emulators.MemoryWriteHookable):
                raise NotImplementedError("Emulator does not support write hooking")
            emulator.hook_memory_write(self.address, self.address + self.size, self.on_write)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({hex(self.address)})"
