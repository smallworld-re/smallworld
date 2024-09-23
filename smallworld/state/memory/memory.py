from ... import emulators, platforms
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
            data = value.get_content()
            result = (
                result[:offset]
                + data.to_bytes(byteorder=byteorder)
                + result[offset + value.size :]
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

    def _is_safe(self, value: state.Value):
        if (self.get_used() + value.get_size()) > self.get_capacity():
            raise ValueError("Stack is full")

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.write_memory(
            self.address, self.to_bytes(byteorder=emulator.platform.byteorder)
        )

    def extract(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError("extracting memory not yet implemented")


__all__ = ["Memory"]
