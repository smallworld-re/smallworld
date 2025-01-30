import os
import typing

import claripy

from ... import emulators, exceptions, platforms
from .. import state


class Memory(state.Stateful, dict):
    """A memory region.

    A memory maps integer offsets (implicitly from the base ``address``)
    to ``Value`` objects.
    """

    def __init__(self, address: int, size: int, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.address: int = address
        """The start address of this memory region."""

        self.size: int = size
        """The size address of this memory region."""

    def to_bytes(self, byteorder: platforms.Byteorder) -> bytes:
        """Convert this memory region into a byte string.

        Missing/undefined space will be filled with zeros.

        Arguments:
            byteorder: Byteorder for conversion to raw bytes.

        Returns:
            Bytes for this object with the given byteorder.
        """

        result = b"\x00" * self.size
        for offset, value in self.items():
            # data = value.get_content()
            result = (
                result[:offset]
                + value.to_bytes(byteorder=byteorder)
                + result[offset + value.get_size() :]
            )

        return result

    def get_capacity(self) -> int:
        """Gets the total number of bytes this memory region can store.
        Returns:
                    The total number of bytes this memory region can store.
        """
        return self.size

    def get_used(self) -> int:
        """Gets the number of bytes written to this memory region.

        Returns:
            The number of bytes written to this memory region.
        """
        return sum([v.get_size() for v in self.values()])

    def get_size(self) -> int:
        raise NotImplementedError("You probably want get_capacity()")

    def _is_safe(self, value: state.Value):
        if (self.get_used() + value.get_size()) > self.get_capacity():
            raise ValueError("Stack is full")

    def _write_content(
        self, emulator: emulators.Emulator, address: int, value: state.Value
    ):
        # Internal stub; makes it easy for Code to switch to write_code()
        content = value.get_content()
        if isinstance(content, claripy.ast.bv.BV):
            try:
                emulator.write_memory_content(address, content)
                return
            except exceptions.SymbolicValueError:
                pass
        emulator.write_memory_content(
            address, value.to_bytes(emulator.platform.byteorder)
        )

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.map_memory(self.address, self.get_capacity())
        for offset, value in self.items():
            if value.get_content() is not None:
                self._write_content(emulator, self.address + offset, value)
            if value.get_type() is not None:
                emulator.write_memory_type(
                    self.address + offset, value.get_size(), value.get_type()
                )
            if value.get_label() is not None:
                emulator.write_memory_label(
                    self.address + offset, value.get_size(), value.get_label()
                )

    def extract(self, emulator: emulators.Emulator) -> None:
        value: state.Value
        try:
            bytes = emulator.read_memory(self.address, self.get_capacity())
            value = state.BytesValue(bytes, f"Extracted memory from {self.address}")
        except exceptions.SymbolicValueError:
            expr = emulator.read_memory_symbolic(self.address, self.get_capacity())
            value = state.SymbolicValue(
                self.get_capacity(), expr, None, f"Extracted memory from {self.address}"
            )
        except Exception as e:
            raise exceptions.EmulationError(
                f"Failed reading {hex(self.address)}"
            ) from e
        self.clear()
        self[0] = value

    def __hash__(self):
        return super(dict, self).__hash__()


class RawMemory(Memory):
    @classmethod
    def from_bytes(cls, bytes: bytes, address: int):
        """Load from a byte array.

        Arguments:
            bytes: The bytes of the memory.
            address: The address where this memory should be loaded
               into an emulator's memory.

        Returns:
            A RawMemory contstructed from the given bytes.
        """

        memory = cls(address=address, size=len(bytes))
        memory[0] = state.BytesValue(bytes, None)

        return memory

    @classmethod
    def from_file(
        cls, file: typing.BinaryIO, address: int, label: typing.Optional[str] = None
    ):
        """Load from an open file-like object.

        Arguments:
            file: The open file-like object from which to load data.
            address: The address where this memory should be loaded
               into an emulator's memory.

        Returns:
            A RawMemory from the given file-like object.
        """

        data, size = file.read(), file.tell()

        memory = cls(address=address, size=size)
        memory[0] = state.BytesValue(data, label)

        return memory

    @classmethod
    def from_filepath(cls, path: str, address: int):
        """Load from a file.

        Arguments:
            path: The path to the file.
            address: The address where this memory should be loaded
               into an emulator's memory.

        Returns:
            A RawMemory parsed from the given file path.
        """

        path = os.path.abspath(os.path.expanduser(path))

        with open(path, "rb") as f:
            return cls.from_file(file=f, address=address)


__all__ = ["Memory", "RawMemory"]
