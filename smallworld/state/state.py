import abc
import typing

from .. import emulators, platforms


class Stateful(metaclass=abc.ABCMeta):
    """System state that can be applied to/loaded from an emulator."""

    @abc.abstractmethod
    def extract(self, emulator: emulators.Emulator) -> None:
        """Load state from an emulator.

        Arguments:
            emulator: The emulator from which to load
        """

    @abc.abstractmethod
    def apply(self, emulator: emulators.Emulator) -> None:
        """Apply state to an emulator.

        Arguments:
            emulator: The emulator to which state should applied.
        """


class Value(Stateful):
    """An individual state value."""

    _content: typing.Optional[typing.Any] = None
    _type: typing.Optional[typing.Any] = None
    _label: typing.Optional[str] = None

    @abc.abstractmethod
    def get_size(self) -> int:
        """Get the size of this object.

        Returns:
            The size this object should occupy in memory.
        """

        return 0

    def get_content(self) -> typing.Optional[typing.Any]:
        """Get the content of this object.

        Returns:
            The content of this object.
        """

        return self._content

    def set_content(self, content: typing.Optional[typing.Any]) -> None:
        """Set the content of this object.

        Arguments:
            content: The content value to set.
        """

        self._content = content

    def get_type(self) -> typing.Optional[typing.Any]:
        """Get the type of this object.

        Returns:
            The type of this object.
        """

        return self._type

    def set_type(self, type: typing.Optional[typing.Any]) -> None:
        """Set the type of this object.

        Arguments:
            type: The type value to set.
        """

        self._type = type

    def get_label(self) -> typing.Optional[str]:
        """Get the label of this object.

        Returns:
            The label of this object.
        """

        return self._label

    def set_label(self, label: typing.Optional[str]) -> None:
        """Set the label of this object.

        Arguments:
            type: The label value to set.
        """

        self._label = label

    def get(self) -> typing.Optional[typing.Any]:
        """A helper to get the content of this object.

        Returns:
            The content of this object.
        """

        return self.get_content()

    def set(self, content: typing.Optional[typing.Any]) -> None:
        """A helper to set the content of this object.

        Arguments:
            content: The content value to set.
        """

        self.set_content(content)

    @abc.abstractmethod
    def to_bytes(self, byteorder: platforms.Byteorder) -> bytes:
        """Convert this object into a byte string.

        Arguments:
            byteorder: Byteorder for conversion to raw bytes.

        Returns:
            Bytes for this object with the given byteorder.
        """

        return b""

    @classmethod
    def from_ctypes(cls, value: typing.Any):
        """Load from an existing ctypes object."""

        raise NotImplementedError("loading from ctypes is not yet implemented")


class Register(Value):
    """An individual register.

    Arguments:
        name: The canonical name of the register.
        size: The size (in bytes) of the register.
    """

    _content: typing.Optional[int] = None
    _type = None
    _label = None

    def __init__(self, name: str, size: int = 4):
        super().__init__()

        self.name: str = name
        """Canonical name."""

        self.size = size
        """Register size in bytes."""

    def get_size(self) -> int:
        return self.size

    def extract(self, emulator: emulators.Emulator) -> None:
        self.set_content(emulator.read_register_content(self.name))
        self.set_type(emulator.read_register_type(self.name))
        self.set_label(emulator.read_register_label(self.name))

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.write_register_content(self.name, self.get_content())
        emulator.write_register_type(self.name, self.get_type())
        emulator.write_register_label(self.name, self.get_label())

    def to_bytes(self, byteorder: platforms.Byteorder) -> bytes:
        value = self.get_content()

        if byteorder == platforms.Byteorder.LITTLE:
            return value.to_bytes(self.size, byteorder="little")
        elif byteorder == platforms.Byteorder.BIG:
            return value.to_bytes(self.size, byteorder="big")
        else:
            raise ValueError(f"unsupported byteorder {byteorder}")


class RegisterAlias(Register):
    """An alias to a partial register.

    Arguments:
        name: The cannonical name of the register.
        reference: A register which this alias references.
        size: The size (in bytes) of the register.
        offset: The offset from the start of the register that this alias
            references.

    """

    def __init__(self, name: str, reference: Register, size: int = 4, offset: int = 0):
        super().__init__(name, size)

        self.reference: Register = reference
        """The register referenced by this alias."""

        self.offset: int = offset
        """'The offset into the referenced register."""

    @property
    def mask(self) -> int:
        mask = (1 << self.size * 8) - 1
        mask <<= self.offset * 8

        return mask

    def extract(self, emulator: emulators.Emulator) -> None:
        self.reference.extract(emulator)

        value = self.reference.get_content() & self.mask
        value >>= self.offset * 8

        self.set_content(value)
        self.set_type(self.reference.get_type())
        self.set_label(self.reference.get_label())

    def apply(self, emulator: emulators.Emulator) -> None:
        value = self.reference.get_content()
        value = (value & ~self.mask) + self.get_content()

        self.reference.set_content(value)
        self.reference.set_type(self.get_type())
        self.reference.set_label(self.get_label())


class Memory(Stateful, dict):
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

    def get_allocated_size(self) -> int:
        """Gets the allocated size of this memory region.

        Returns:
            The allocated size of this memory region.
        """

        return sum([v.get_size() for v in self.values()])

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.write_memory(
            self.address, self.to_bytes(byteorder=emulator.platform.byteorder)
        )

    def extract(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError("extracting memory not yet implemented")


class Code(Memory):
    pass


class StatefulSet(Stateful, set):
    def extract(self, emulator: emulators.Emulator) -> None:
        for stateful in self:
            stateful.extract(emulator)

    def apply(self, emulator: emulators.Emulator) -> None:
        for stateful in self:
            stateful.apply(emulator)


class Machine(StatefulSet):
    pass


__all__ = [
    "Stateful",
    "Value",
    "Register",
    "RegisterAlias",
    "Memory",
    "Code",
    "Machine",
]
