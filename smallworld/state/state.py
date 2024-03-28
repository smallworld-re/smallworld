import abc
import ctypes
import logging
import re
import textwrap
import typing

from .. import emulators, initializers

logger = logging.getLogger(__name__)


class Value(metaclass=abc.ABCMeta):
    """A state value storage base class.

    Defines the interface for a single system state value.
    """

    @property
    @abc.abstractmethod
    def value(self):
        """Get the internaly stored value.

        Returns:
            Some internal value type.
        """

        pass

    @value.setter
    @abc.abstractmethod
    def value(self, value) -> None:
        """Set the internally stored value.

        Arguments:
            value: Some internal value type.
        """

        pass

    type: typing.Any = None
    """Optinal type information."""

    label: typing.Any = None
    """Optional label information."""

    @abc.abstractmethod
    def initialize(
        self, initializer: initializers.Initializer, override: bool = False
    ) -> None:
        """Set the internally stored value using an initialization strategy.

        Arguments:
            initializer: Initialization strategy instance.
            override: If `True` override existing values, otherwise keep
                them. Default: `False`.
        """

        pass

    @abc.abstractmethod
    def load(self, emulator: emulators.Emulator, override: bool = True) -> None:
        """Load the state value.

        Arguments:
            emulator: Emulator from which to load state.
            override: If `True` override existing values, otherwise keep
                them. Default: `True`.
        """

        pass

    @abc.abstractmethod
    def apply(self, emulator: emulators.Emulator) -> None:
        """Apply state value to an emulator.

        Arguments:
            emulator: Emulator to which state should be applied.
        """

        pass

    @abc.abstractmethod
    def __repr__(self) -> str:
        """Instance stringifier.

        Implementation required.
        """

        return ""


class Code(Value):
    """An executable image and metadata storage class.

    Arguments:
        image: The actual bytes of the executable.
        type: Executable format ("blob", "PE", "ELF", etc.)
        arch: Architecture ("x86", "arm", etc.)
        mode: Architecture mode ("32", "64", etc.)
        base: Base address.
        entry: Execution entry address.
        exits: Exit addresses - used to determine when execution has
            terminated.
    """

    def __init__(
        self,
        image: bytes,
        type: typing.Optional[str] = None,
        arch: typing.Optional[str] = None,
        mode: typing.Optional[str] = None,
        base: typing.Optional[int] = None,
        entry: typing.Optional[int] = None,
        exits: typing.Optional[typing.Iterable[int]] = None,
    ):
        super().__init__()

        self.image = image
        self.type = type
        self.arch = arch
        self.mode = mode
        self.base = base
        self.entry = entry
        self.exits = exits or []

    @classmethod
    def from_filepath(cls, path: str, *args, **kwargs):
        with open(path, "rb") as f:
            image = f.read()

        return cls(image, *args, **kwargs)

    @property
    def value(self):
        raise NotImplementedError()

    @value.setter
    def value(self, value) -> None:
        raise NotImplementedError()

    def initialize(
        self, initializer: initializers.Initializer, override: bool = False
    ) -> None:
        logger.debug(f"skipping initialization for {self} (code)")

    def load(self, emulator: emulators.Emulator, override: bool = True) -> None:
        logger.debug(f"{self} loading not supported - load skipped")

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.load(self)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(type={self.type}, arch={self.arch}, mode={self.mode}, base={self.base}, entry={self.entry}, exits={self.exits})"


class Register(Value):
    """A register value.

    Arguments:
        name: The canonical name of the register.
        width: The size (in bytes) of the register.
    """

    def __init__(self, name: str, width: int = 4):
        super().__init__()

        self.name = name
        self.width = width
        self._value: typing.Optional[int] = None

    @property
    def value(self) -> typing.Optional[int]:
        return self._value

    @value.setter
    def value(self, value: int) -> None:
        if value.bit_length() > self.width * 8:
            raise ValueError(f"{value} is too large for {self}")
        logger.debug(f"initializing value {self}")
        self._value = value

    def initialize(
        self, initializer: initializers.Initializer, override: bool = False
    ) -> None:
        if self.value is not None and not override:
            logger.debug(f"skipping initialization for {self} (already initialized)")
            return

        if self.width == 1:
            self.value = initializer.char()
        elif self.width == 2:
            self.value = initializer.short()
        elif self.width == 4:
            self.value = initializer.word()
        elif self.width == 8:
            self.value = initializer.dword()
        else:
            raise ValueError("unsupported register width for initialization")

    def load(self, emulator: emulators.Emulator, override: bool = True) -> None:
        if self.value is not None and not override:
            logger.debug(f"skipping load for {self} (already loaded)")
            return

        self.value = emulator.read_register(self.name)

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.write_register(self.name, self.value)

    def __repr__(self) -> str:
        if self.value is not None:
            rep = f"{self.name}=0x{self.value:x}"
        else:
            rep = f"{self.name}"

        return f"Register({rep})"


class RegisterAlias(Register):
    """An alias to a partial register.

    Arguments:
        name: The canonical name of the register.
        reference: A register which this alias references.
        width: The size (in bytes) of the register.
        offset: The offset from the start of the register that this alias
            references.
    """

    def __init__(self, name: str, reference: Register, width: int = 4, offset: int = 0):
        super().__init__(name, width)

        self.reference = reference
        self.offset = offset

    @property
    def mask(self) -> int:
        """Generate a mask for this partial register."""

        mask = (1 << self.width * 8) - 1
        mask <<= self.offset * 8

        return mask

    @property
    def value(self) -> typing.Optional[int]:
        reference = self.reference.value

        if reference is None:
            return None

        value = reference & self.mask
        value >>= self.offset * 8

        return value

    @value.setter
    def value(self, value: int) -> None:
        if value.bit_length() > self.width * 8:
            raise ValueError(f"{value} is too large for {self}")

        reference = self.reference.value or 0

        result = (reference & ~self.mask) + value

        self.reference.value = result

    def initialize(
        self, initializer: initializers.Initializer, override: bool = False
    ) -> None:
        logger.debug(f"skipping initialization for {self} (alias)")

    def load(self, emulator: emulators.Emulator, override: bool = True) -> None:
        """Register references store no value, so this does nothing."""

        logger.debug(f"{self} is a register reference - load skipped")

    def apply(self, emulator: emulators.Emulator) -> None:
        """Register references store no value, so this does nothing."""

        logger.debug(f"{self} is a register reference - apply skipped")


class Memory(Value):
    """A memory region base class.

    Arguments:
        address: The address of this memory region.
        size: The size (in bytes) of this memory region.
    """

    def __init__(self, address: int, size: int, byteorder="little"):
        super().__init__()

        self.address = address
        self.size = size
        self.byteorder = byteorder
        self.memory = b""

    def initialize(
        self, initializer: initializers.Initializer, override: bool = False
    ) -> None:
        if self.value is not None and not override:
            logger.debug(f"skipping initialization for {self} (already initialized)")
            return

        self.value = initializer.generate(self.size)

    def load(self, emulator: emulators.Emulator, override: bool = True) -> None:
        if self.value is not None and not override:
            logger.debug(f"skipping load for {self} (already loaded)")
            return

        value = emulator.read_memory(self.address, self.size)

        if value:
            self.value = value
        else:
            raise ValueError(
                f"failed to load {self.size} bytes from 0x{self.address:x}"
            )

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.write_memory(self.address, self.value)

    @property
    def value(self) -> typing.Optional[bytes]:
        return self.memory

    @value.setter
    def value(self, value: bytes) -> None:
        if len(value) > self.size:
            raise ValueError("buffer too large for this memory region")

        self.memory = value

    def __repr__(self) -> str:
        value_bytes = self.value
        if value_bytes is not None:
            value_bytes = value_bytes[:100]
            value = value_bytes.decode(errors="replace")
            value = textwrap.shorten(value, width=32)

            rep = f'{self.address:x}="{value}"[{self.size}]'
        else:
            rep = f"{self.address:x}->{self.address + self.size:x}[{self.size}]"

        return f"Memory({rep})"

    def to_bytes(self, value, size: typing.Optional[int] = None) -> bytes:
        """Convert a given value to bytes.

        Arguments:
            value: Object to be converted.
            size: Size.
        """

        if type(value) in (bytes, bytearray):
            return value
        elif type(value) is int:
            if size is None:
                raise ValueError("need a size to convert int to bytes")
            return value.to_bytes(size, byteorder=self.byteorder)
        elif isinstance(value, ctypes.Structure):  # type(value) is ctypes.Structure:
            return bytes(value)
        else:
            raise NotImplementedError(f"unsupported type: {type(value)}")


class Stack(Memory):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.memory: typing.List[typing.Tuple(bytes, int)] = []
        self.used = 0

    @property
    def value(self) -> typing.Optional[bytes]:
        value = bytearray()

        for v, s in self.memory:
            value += self.to_bytes(v, s)

        return value

    @value.setter
    def value(self, value: bytes) -> None:
        if len(value) > self.size:
            raise ValueError("buffer too large for this memory region")

        # Best effort value retrieval.
        #
        # We don't know what all has changed since this was initially set, so
        # there's no way to split the value read out of an Emulator into
        # individual stack values. The best we can do is treat the entire
        # region as a single allocation.

        self.memory = [(value, len(value))]
        self.used = len(value)

    def push(self, value, size=None):
        allocation = len(self.to_bytes(value, size))

        if self.used + allocation > self.size:
            raise ValueError(f"{value} (size: {allocation}) is too large for {self}")

        self.memory.append((value, size))
        self.used += allocation


class Heap(Memory):
    @abc.abstractmethod
    def malloc(self, value, size: typing.Optional[int] = None) -> int:
        """Place a value on the heap.

        Arguments:
            value: Object to be allocated.
            size: Size.

        Returns:
            The address of the value allocated.
        """

        return 0

    @abc.abstractmethod
    def free(self, address: int) -> None:
        """Free a value from the heap.

        Arguments:
            address: The address of the object to free.
        """

        pass


class BumpAllocator(Heap):
    """A simple stack-like heap implementation."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.memory: typing.List[typing.Tuple[bytes, int]] = []
        self.used = 0

    @property
    def value(self) -> typing.Optional[bytes]:
        value = bytearray()

        for v, s in self.memory:
            value += self.to_bytes(v, s)

        return value

    @value.setter
    def value(self, value: bytes) -> None:
        if len(value) > self.size:
            raise ValueError("buffer too large for this memory region")

        # Best effort value retrieval - see comment in `Stack.value`.

        self.memory = [(value, len(value))]
        self.used = len(value)

    def malloc(self, value, size: typing.Optional[int] = None) -> int:
        allocation = self.to_bytes(value, size)

        if size is None:
            size = len(allocation)

        if self.used + size > self.size:
            raise ValueError(
                f"{value} (size: {len(allocation)}) is too large for {self}"
            )

        address = self.address + self.used
        self.memory.append((allocation, size))
        self.used += size

        return address

    def free(self, address: int) -> None:
        raise NotImplementedError()


class State(Value):
    """A collection of state values, loaded and applied as a group."""

    def map(self, value: Value, name: typing.Optional[str] = None) -> None:
        """Map a given Value into this state object.

        Arguments:
            value: Value to map.
            name: Attribute name - if not provided a reasonable default will be
                chosen based on the Value class name and the attributes already
                present on this State.
        """

        if name is None:
            name = value.__class__.__name__.lower()

            logger.debug(f"mapping name not provided, using {name}")

            if hasattr(self, name):
                candidates = []
                for attribute in dir(self):
                    for match in re.findall(f"{name}(\\d*)$", attribute):
                        candidates.append(int(match or 0))
                name = f"{name}{max(candidates) + 1}"

                logger.debug(f"mapping name colision detected - using {name} instead")
        else:
            if hasattr(self, name):
                raise ValueError(f"{name} already exists on {self}")

        setattr(self, name, value)

    def members(
        self, filter: typing.Optional[typing.Type] = None
    ) -> typing.Dict[str, Value]:
        """Members that comprise this state.

        Gather the list of included state values as any class members that are
        subclasses of Value.

        This is similar to python 3.11's `inspect.getmembers_static`.

        Arguments:
            filter: Optional value type filter - a subclass of Value which
                should be returned.

        Returns:
            A dictionary mapping names to state value objects.
        """

        members = {}
        for member in dir(self):
            if member in ["members", "value", "type", "label"]:
                continue
            value = getattr(self, member)
            if isinstance(value, Value):
                if not filter or type(value) is filter:
                    members[member] = value

        return members

    @property
    def value(self) -> typing.Dict[str, typing.Any]:
        """Get the internaly stored values.

        Returns:
            A dict mapping state value names to internal values.
        """

        return {k: v.value for k, v in self.members().items()}

    @value.setter
    def value(self, value: typing.Dict[str, typing.Any]) -> None:
        """Set the internally stored values.

        Arguments:
            value: A dict mapping state value names to internal values.
        """

        for name, state in self.members().items():
            if name in value:
                state.value = value[name]
                value.pop(name)

        if value:
            raise ValueError(f"unknown state members: {list(value.keys())}")

    @property
    def type(self) -> typing.Dict[str, typing.Any]:
        """Get the internaly stored types.

        Returns:
            A dict mapping state value names to internal types.
        """

        return {k: v.type for k, v in self.members().items()}

    @type.setter
    def type(self, value: typing.Dict[str, typing.Any]) -> None:
        """Set the internally stored types.

        Arguments:
            value: A dict mapping state value names to internal types.
        """

        for name, state in self.members().items():
            if name in value:
                state.type = value[name]
                value.pop(name)

        if value:
            raise ValueError(f"unknown state members: {list(value.keys())}")

    @property
    def label(self) -> typing.Dict[str, typing.Any]:
        """Get the internaly stored labels.

        Returns:
            A dict mapping state value names to internal labels.
        """

        return {k: v.label for k, v in self.members().items()}

    @label.setter
    def label(self, value: typing.Dict[str, typing.Any]) -> None:
        """Set the internally stored labels.

        Arguments:
            value: A dict mapping state value names to internal labels.
        """

        for name, state in self.members().items():
            if name in value:
                state.label = value[name]
                value.pop(name)

        if value:
            raise ValueError(f"unknown state members: {list(value.keys())}")

    def initialize(
        self, initializer: initializers.Initializer, override: bool = False
    ) -> None:
        logger.info(f"initializing {self} with {initializer}")

        for name, state in self.members().items():
            state.initialize(initializer, override=override)

    def load(self, emulator: emulators.Emulator, override: bool = True) -> None:
        for name, state in self.members().items():
            state.load(emulator, override=override)
            logger.debug(f"loaded {name}:{state} from {emulator}")

    def apply(self, emulator: emulators.Emulator) -> None:
        for name, state in self.members().items():
            logger.debug(f"applying {name}:{state} to {emulator}")
            state.apply(emulator)

    def __repr__(self) -> str:
        joined = ", ".join([str(v) for v in self.members().values()])
        joined = textwrap.shorten(joined, width=64)

        return f"{self.__class__.__name__}({joined})"


class CPU(State):
    """Some additional required properties of CPUs."""

    @property
    @abc.abstractmethod
    def arch(self) -> str:
        """Processor architecture (e.g., x86)."""

        return ""

    @property
    @abc.abstractmethod
    def mode(self) -> str:
        """Processor mode (e.g., 64)."""

        return ""


__all__ = [
    "Value",
    "Code",
    "Register",
    "RegisterAlias",
    "Memory",
    "Stack",
    "Heap",
    "BumpAllocator",
]
