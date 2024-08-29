import abc
import typing

from .. import emulators, platform


class Stateful(metaclass=abc.ABCMeta):
    """System state that can be applied to/loaded from an emulator."""

    @abc.abstractmethod
    def get(emulator: emulators.Emulator) -> None:
        """Load state from an emulator.

        Arguments:
            emulator: The emulator from which to load state.
        """

    @abc.abstractmethod
    def set(emulator: emulators.Emulator) -> None:
        """Apply state to an emulator.

        Arguments:
            emulator: The emulator to which state should applied.
        """


class Value(Stateful):
    """An individual state value."""

    content: typing.Optional[typing.Any] = None
    """Stored value."""

    type: typing.Optional[typing.Any] = None
    """Type object/class."""

    label: typing.Optional[str] = None
    """A useful label."""

    size: int = 0
    """Size in bytes."""

    @abc.abstractmethod
    def to_bytes(self, byteorder: platform.Byteorder) -> bytes:
        """Convert content to bytes."""

        return b""

    @classmethod
    def from_ctypes(cls, value: typing.Any):
        """Load from an existing ctypes object."""

        raise NotImplementedError("TODO")


class Register(Value):
    """An individual register.

    Arguments:
        name: The canonical name of the register.
        size: The width (in bytes) of the register.
    """

    content: typing.Optional[int] = None
    type = None
    label = None

    size = 0
    """Register width in bytes."""

    def __init__(self, name: str, size: int = 4):
        super().__init__()

        self.name: str = name
        """Canonical name."""

        self.size = size

    def get(self, emulator: emulators.Emulator) -> None:
        self.content = emulator.read_register_content(self.name)
        self.type = emulator.read_register_type(self.name)
        self.label = emulator.read_register_label(self.name)

    def set(self, emulator: emulators.Emulator) -> None:
        emulator.write_register_content(self.name, self.content)
        emulator.write_register_type(self.name, self.type)
        emulator.write_register_label(self.name, self.label)


def RegisterAlias(Register):
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

        self.offset = offset
        """'The offset into the referenced register."""

    @property
    def mask(self) -> int:
        """Generate a mask for this partial register."""

        mask = (1 << self.width * 8) - 1
        mask <<= self.offset * 8

        return mask

    def get(self, emulator: emulators.Emulator) -> None:
        self.reference.get(emulator)

        self.content = self.reference.content & self.mask
        self.content >>= self.offset * 8

        self.type = self.reference.type
        self.label = self.reference.label

    def set(self, emulator: emulators.Emulator) -> None:
        reference = self.reference.content or 0
        result = (reference & ~self.mask) + value
        self.reference.content = result

        self.reference.type = self.type
        self.reference.label = self.label

        self.reference.set(emulator)


__all__ = ["Stateful", "Value", "Register", "RegisterAlias"]
