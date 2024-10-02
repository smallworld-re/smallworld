from ... import emulators, platforms, exceptions
from .. import state


class Memory(state.Stateful, state.Value, dict):
    """A memory region.

    This dictionary maps integer offsets from the base ``address`` to ``Value``
    classes.
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
            #data = value.get_content()
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
        raise NotImplemented("You probably want get_capacity()")

    def _is_safe(self, value: state.Value):
        if (self.get_used() + value.get_size()) > self.get_capacity():
            raise ValueError("Stack is full")

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.map_memory(self.get_capacity(), self.address)
        for offset, value in self.items():
            if not isinstance(value, state.EmptyValue):
                emulator.write_memory_content(self.address + offset, value.to_bytes(emulator.platform.byteorder))
            if value.get_type() is not None:
                emulator.write_memory_type(self.address + offset, value.get_size(), value.get_type())
            if value.get_label() is not None:
                emulator.write_memory_label(self.address + offset, value.get_size(), value.get_label())

    def extract(self, emulator: emulators.Emulator) -> None:
        try:
            bytes = emulator.read_memory(self.address, self.get_capacity())
            value = state.BytesValue(bytes, f"Extracted memory from {self.address}")
        except exceptions.SymbolicValueError:
            value = state.EmptyValue(self.get_capacity(), None, f"Extracted memory from {self.address}")
        self[0] = value


__all__ = ["Memory"]
