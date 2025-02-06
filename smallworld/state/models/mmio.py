import abc
import logging
import typing

import claripy

from ... import emulators
from .. import state

logger = logging.getLogger(__name__)


class MemoryMappedModel(state.Stateful):
    """A model of a memory-mapped IO device dealing with concrete values

    This lets you specify alternate handler routines
    for reads and writes within a range of memory addressess,
    bypassing the emulator's normal memory model.
    As the name suggests, this is useful for modeling
    MMIO devices, where accessing a particular address
    actually accesses a register of a peripheral device.

    The callback routines on_read() and on_write()
    will trigger on any access within the specified range;
    one MemoryMappedModel can handle multiple registers,
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
    def on_read(
        self, emu: emulators.Emulator, addr: int, size: int, unused: bytes
    ) -> typing.Optional[bytes]:
        """Callback handling reads from an MMIO register

        NOTE: Results must be encoded in the emulator's byte order.

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

        NOTE: Attempting to access memory in this MMIO range
        inside this handler will produce undefined behavior.

        Arguments:
            emu: The emulator object mediating this operation
            addr: The start address of the write operation
            size: The number of bytes written
            value: The bytes written
        """
        raise NotImplementedError("Abstract method")

    def extract(self, emulator: emulators.Emulator) -> None:
        logger.debug(f"Skipping extract for {self} (mmio)")

    def apply(self, emulator: emulators.Emulator) -> None:
        logger.debug(f"Hooking MMIO {self} {self.address:x}")
        emulator.map_memory(self.address, self.size)
        if self.on_read is not None:
            if not isinstance(emulator, emulators.MemoryReadHookable):
                raise NotImplementedError("Emulator does not support read hooking")
            emulator.hook_memory_read(
                self.address, self.address + self.size, self.on_read
            )
        if self.on_write is not None:
            if not isinstance(emulator, emulators.MemoryWriteHookable):
                raise NotImplementedError("Emulator does not support write hooking")
            emulator.hook_memory_write(
                self.address, self.address + self.size, self.on_write
            )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({hex(self.address)})"


class SymbolicMemoryMappedModel(state.Stateful):
    """A model of a memory-mapped IO device dealing with symbolic values

    This lets you specify alternate handler routines
    for reads and writes within a range of memory addressess,
    bypassing the emulator's normal memory model.
    As the name suggests, this is useful for modeling
    MMIO devices, where accessing a particular address
    actually accesses a register of a peripheral device.

    The callback routines on_read() and on_write()
    will trigger on any access within the specified range;
    one MemoryMappedModel can handle multiple registers,
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
    def on_read(
        self, emu: emulators.Emulator, addr: int, size: int, unused: claripy.ast.bv.BV
    ) -> typing.Optional[claripy.ast.bv.BV]:
        """Callback handling reads from an MMIO register

        NOTE: Results must be encoded in the emulator's byte order.

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
        self, emu: emulators.Emulator, addr: int, size: int, value: claripy.ast.bv.BV
    ) -> None:
        """Callback handling writes to an MMIO register

        NOTE: `value` will be encoded in the emulator's byte order.

        NOTE: Attempting to access memory in this MMIO range
        inside this handler will produce undefined behavior.

        Arguments:
            emu: The emulator object mediating this operation
            addr: The start address of the write operation
            size: The number of bytes written
            value: The bytes written
        """
        raise NotImplementedError("Abstract method")

    def extract(self, emulator: emulators.Emulator) -> None:
        logger.debug(f"Skipping extract for {self} (mmio)")

    def apply(self, emulator: emulators.Emulator) -> None:
        logger.debug(f"Hooking MMIO {self} {self.address:x}")
        emulator.map_memory(self.address, self.size)
        if self.on_read is not None:
            if not isinstance(emulator, emulators.MemoryReadHookable):
                raise NotImplementedError("Emulator does not support read hooking")
            emulator.hook_memory_read_symbolic(
                self.address, self.address + self.size, self.on_read
            )
        if self.on_write is not None:
            if not isinstance(emulator, emulators.MemoryWriteHookable):
                raise NotImplementedError("Emulator does not support write hooking")
            emulator.hook_memory_write_symbolic(
                self.address, self.address + self.size, self.on_write
            )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({hex(self.address)})"
