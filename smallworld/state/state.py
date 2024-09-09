import abc
import typing

from .. import emulators, platform, utils
import smallworld

class Stateful(metaclass=abc.ABCMeta):
    """System state that can be applied to/loaded from an emulator."""

    @abc.abstractmethod
    def extract(self, emulator: emulators.Emulator) -> None:
        """Load state from an emulator.

        Arguments:
            emulator: The emulator from which to load state.
        """

    @abc.abstractmethod
    def apply(self, emulator: emulators.Emulator) -> None:
        """Apply state to an emulator.

        Arguments:
            emulator: The emulator to which state should applied.
        """

class StatefulSet(Stateful):
    def __init__(self):
        self._states = []

    def extract(self, emulator: emulators.Emulator) -> None:
        for s in self._states:
            s.extract(emulator)

    def apply(self, emulator: emulators.Emulator) -> None:
        for s in self._states:
            s.apply(emulator)

    def add(self, s: Stateful):
        self._states.append(s)

class CPU(StatefulSet):
    @classmethod
    @abc.abstractmethod
    def get_platform(self) -> platform.Platform:
        pass

    @classmethod
    def for_platform(cls, platform: platform.Platform):
        try:
            return utils.find_subclass(cls,lambda x: x.get_platform().architecture == platform.architecture and x.get_platform().byteorder == platform.byteorder)
        except ValueError:
            raise ValueError(f"No CPU model for {platform.architecture}:{platform.byteorder}")

    def __repr__(self) -> str:
        p = self.get_platform()
        return f"{p.architecture} - {p.byteorder}"

class AMD64(CPU):
    @classmethod
    def get_platform(cls) -> platform.Platform:
        return platform.Platform(platform.Architecture.X86_64, platform.Byteorder.LITTLE, platform.ABI.NONE)

    def __init__(self):
        super().__init__()
        # This is temporary
        self.rax = Register("rax", 8)
        self.rip = Register("rip", 8)
        self.edi = Register("edi", 4)

class Machine(StatefulSet):
    pass

class Value(Stateful):
    """An individual state value."""

    _content: typing.Optional[typing.Any] = None
    """Stored value."""

    _type: typing.Optional[typing.Any] = None
    """Type object/class."""

    _label: typing.Optional[str] = None
    """A useful label."""

    size: int = 0
    """Size in bytes."""

    def get(self):
        return self.get_content()

    def set(self, content):
        return self.set_content(content)

    def get_content(self):
        return self._content

    def set_content(self, content):
        self._content = content

    def get_type(self):
        return self._type

    def set_type(self, type):
        self._type = type

    def get_label(self):
        return self._label

    def set_label(self, label):
        self._label = label

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

    _content: typing.Optional[int] = None
    _type = None
    _label = None

    size = 0
    """Register width in bytes."""

    def __init__(self, name: str, size: int = 4):
        super().__init__()

        self.name: str = name
        """Canonical name."""

        self.size = size

    def extract(self, emulator: emulators.Emulator) -> None:
        self._content = emulator.read_register_content(self.name)
        self._type = emulator.read_register_type(self.name)
        self._label = emulator.read_register_label(self.name)

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.write_register_content(self.name, self._content)
        emulator.write_register_type(self.name, self._type)
        emulator.write_register_label(self.name, self._label)


    def to_bytes(self, byteorder: platform.Byteorder) -> bytes:
        """Convert content to bytes."""
        if byteorder == platform.Byteorder.LITTLE:
            return self._content.to_bytes(self.size, byteorder='little')
        elif byteorder == platform.Byteorder.BIG:
            return self._content.to_bytes(self.size, byteorder='big')
        else:
            b""

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

        self.offset = offset
        """'The offset into the referenced register."""

    @property
    def mask(self) -> int:
        """Generate a mask for this partial register."""

        mask = (1 << self.width * 8) - 1
        mask <<= self.offset * 8

        return mask

    def extract(self, emulator: emulators.Emulator) -> None:
        self.reference.get(emulator)

        self.content = self.reference.content & self.mask
        self.content >>= self.offset * 8

        self.type = self.reference.type
        self.label = self.reference.label

    def apply(self, emulator: emulators.Emulator) -> None:
        reference = self.reference.content or 0
        result = (reference & ~self.mask) + value
        self.reference.content = result

        self.reference.type = self.type
        self.reference.label = self.label

        self.reference.set(emulator)

class Memory(Stateful):
    def __init__(self, address, size) -> None:
        super().__init__()
        self._address = address
        self._size = size


    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.write_memory(self._address, self.get_bytes())

    def extract(self, emulator: emulators.Emulator) -> None:
        raise NotImplemented

class Code(Memory):
    pass


__all__ = ["Stateful", "Value", "Register", "RegisterAlias", "Machine", "CPU"]
