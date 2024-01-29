import abc
import logging
import textwrap
import typing

from . import executor, initializer

logger = logging.getLogger(__name__)


class Value(metaclass=abc.ABCMeta):
    """A state value storage base class.

    Defines the interface for a single system state value.
    """

    @abc.abstractmethod
    def get(self):
        """Get the internaly stored value.

        Returns:
            Some internal value type.
        """

        return

    @abc.abstractmethod
    def set(self, value) -> None:
        """Set the internally stored value.

        Arguments:
            value: Some internal value type.
        """

        pass

    @abc.abstractmethod
    def initialize(
        self, initializer: initializer.Initializer, override: bool = False
    ) -> None:
        """Set the internally stored value using an initialization strategy.

        Arguments:
            initializer (Initializer): Initialization strategy instance.
            override (bool): If `True` override existing values, otherwise keep
                them. Default: `False`.
        """

        pass

    @abc.abstractmethod
    def load(self, executor: executor.Executor, override: bool = True) -> None:
        """Load the state value.

        Arguments:
            executor (Executor): Executor from which to load state.
            override (bool): If `True` override existing values, otherwise keep
                them. Default: `True`.
        """

        pass

    @abc.abstractmethod
    def apply(self, executor: executor.Executor) -> None:
        """Apply state value to an executor.

        Arguments:
            executor (Executor): Executor to which state should be applied.
        """

        pass

    @abc.abstractmethod
    def __repr__(self) -> str:
        """Instance stringifier.

        Implementation required.
        """

        return ""


class Register(Value):
    """A register value.

    Arguments:
        name (str): The canonical name of the register.
        width (int): The size (in bytes) of the register.
    """

    def __init__(self, name: str, width: int = 4):
        self.name = name
        self.width = width
        self.value: typing.Optional[int] = None

    def get(self) -> typing.Optional[int]:
        return self.value

    def set(self, value: int) -> None:
        if value.bit_length() > self.width * 8:
            raise ValueError(f"{value} is too large for {self}")
        logger.debug(f"initializing value {self}")
        self.value = value

    def initialize(
        self, initializer: initializer.Initializer, override: bool = False
    ) -> None:
        if self.get() is not None and not override:
            logger.debug(f"skipping initialization for {self} (already initialized)")
            return

        if self.width == 1:
            self.set(initializer.char())
        elif self.width == 2:
            self.set(initializer.short())
        elif self.width == 4:
            self.set(initializer.word())
        elif self.width == 8:
            self.set(initializer.dword())
        else:
            raise ValueError("unsupported register width for initialization")

    def load(self, executor: executor.Executor, override: bool = True) -> None:
        if self.value is not None and not override:
            logger.debug(f"skipping load for {self} (already loaded)")
            return

        self.value = executor.read_register(self.name)

    def apply(self, executor: executor.Executor) -> None:
        executor.write_register(self.name, self.value)

    def __repr__(self) -> str:
        if self.get() is not None:
            rep = f"{self.name}=0x{self.get():x}"
        else:
            rep = f"{self.name}"

        return f"Register({rep})"


class RegisterAlias(Register):
    """An alias to a partial register.

    Arguments:
        name (str): The canonical name of the register.
        reference (Register): A register which this alias references.
        width (int): The size (in bytes) of the register.
        offset (int): The offset from the start of the register that this alias
            references.
    """

    def __init__(self, name: str, reference: Register, width: int = 4, offset: int = 0):
        self.name = name
        self.reference = reference
        self.width = width
        self.offset = offset

    @property
    def mask(self) -> int:
        """Generate a mask for this partial register."""

        mask = (1 << self.width * 8) - 1
        mask <<= self.offset * 8

        return mask

    def get(self) -> typing.Optional[int]:
        reference = self.reference.get()

        if reference is None:
            return None

        value = reference & self.mask
        value >>= self.offset * 8

        return value

    def set(self, value: int) -> None:
        if value.bit_length() > self.width * 8:
            raise ValueError(f"{value} is too large for {self}")

        reference = self.reference.get() or 0

        result = (reference & ~self.mask) + value

        self.reference.set(result)

    def initialize(
        self, initializer: initializer.Initializer, override: bool = False
    ) -> None:
        logger.debug(f"skipping initialization for {self} (alias)")

    def load(self, executor: executor.Executor, override: bool = True) -> None:
        """Register references store no value, so this does nothing."""

        logger.debug(f"{self} is a register reference - load skipped")

    def apply(self, executor: executor.Executor) -> None:
        """Register references store no value, so this does nothing."""

        logger.debug(f"{self} is a register reference - apply skipped")


class Memory(Value):
    """A memory region base class.

    Arguments:
        address (int): The address of this memory region.
        size (int): The size (in bytes) of this memory region.
    """

    def __init__(self, address: int, size: int, byteorder="little"):
        self.address = address
        self.size = size
        self.byteorder = byteorder

    def initialize(
        self, initializer: initializer.Initializer, override: bool = False
    ) -> None:
        if self.get() is not None and not override:
            logger.debug(f"skipping initialization for {self} (already initialized)")
            return

        self.set(initializer.generate(self.size))

    def load(self, executor: executor.Executor, override: bool = True) -> None:
        if self.get() is not None and not override:
            logger.debug(f"skipping load for {self} (already loaded)")
            return

        self.set(executor.read_memory(self.address, self.size))

    def apply(self, executor: executor.Executor) -> None:
        executor.write_memory(self.address, self.get())

    def __repr__(self) -> str:
        if self.get():
            value = self.get().decode("utf-8", errors="replace")
            value = textwrap.shorten(value, width=32)

            rep = f'{self.address:x}="{value}"[{self.size}]'
        else:
            rep = f"{self.address:x}->{self.address + self.size:x}[{self.size}]"

        return f"Memory({rep})"

    def to_bytes(self, value, size: typing.Optional[int] = None):
        """Convert a given value to bytes.

        Arguments:
            value: Object to be converted.
            size (int): Optional size.
        """

        if type(value) in (bytes, bytearray):
            return value
        elif type(value) is int:
            if size is None:
                raise ValueError("need a size to convert int to bytes")
            return value.to_bytes(size, byteorder=self.byteorder)
        else:
            raise NotImplementedError(f"unsupported type: {type(value)}")


class Stack(Memory):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.memory = []
        self.used = 0

    def get(self) -> typing.Optional[bytes]:
        value = bytearray()

        for v, s in self.memory:
            value += self.to_bytes(v, s)

        return value

    def set(self, value: bytes) -> None:
        logger.warning("reading stack from memory not yet implemented")

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
            size (int): Optional size.

        Returns:
            The address of the value allocated.
        """

        return 0

    @abc.abstractmethod
    def free(self, address: int) -> None:
        """Free a value from the heap.

        Arguments:
            address (int): The address of the object to free.
        """

        pass


class BumpAllocator(Heap):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.memory = []
        self.used = 0

    def get(self) -> typing.Optional[bytes]:
        value = bytearray()

        for v, s in self.memory:
            value += self.to_bytes(v, s)

        return value

    def set(self, value: bytes) -> None:
        raise NotImplementedError()

    def malloc(self, value, size: typing.Optional[int] = None) -> int:
        allocation = len(self.to_bytes(value, size))

        if self.used + allocation > self.size:
            raise ValueError(f"{value} (size: {allocation}) is too large for {self}")

        address = self.address + self.used
        self.memory.append((value, size))
        self.used += allocation

        return address

    def free(self, address: int) -> None:
        raise NotImplementedError()


class State(Value):
    """A collection of state values, loaded and applied as a group."""

    def map(self, value: Value, name: typing.Optional[str] = None) -> None:
        """Map a given Value into this state object.

        Arguments:
            value (Value): Value to map.
            name (str): Optional attribute name - defaults to the class name.
        """

        if name is None:
            name = value.__class__.__name__.lower()

        setattr(self, name, value)

    @property
    def values(self) -> typing.Dict[str, Value]:
        """dict[str, Value]: the list of states.

        Gather the list of included state values as any class members that are
        subclasses of Value.

        This is similar to python 3.11's `inspect.getmembers_static`.
        """

        members = {}
        for member in dir(self):
            if member == "values":
                continue
            value = getattr(self, member)
            if isinstance(value, Value):
                members[member] = value

        return members

    def get(self) -> typing.Dict[str, typing.Any]:
        """Get the internaly stored values.

        Returns:
            A dict mapping state value names to internal values.
        """

        return {k: v.get() for k, v in self.values.items()}

    def set(self, value: typing.Dict[str, typing.Any]) -> None:
        """Set the internally stored values.

        Arguments:
            value: A dict mapping state value names to internal values.
        """

        for name, state in self.values.items():
            if name in value:
                state.set(value[name])
                value.pop(name)

        if value:
            raise ValueError(f"unknown state values: {list(value.keys())}")

    def initialize(
        self, initializer: initializer.Initializer, override: bool = False
    ) -> None:
        logger.info(f"initializing {self} with {initializer}")

        for name, state in self.values.items():
            state.initialize(initializer, override=override)

    def load(self, executor: executor.Executor, override: bool = True) -> None:
        for name, state in self.values.items():
            logger.debug(f"loading {name} from {executor}")
            state.load(executor, override=override)

    def apply(self, executor: executor.Executor) -> None:
        for name, state in self.values.items():
            logger.debug(f"applying {name}:{state} to {executor}")
            state.apply(executor)

    def stringify(self, truncate: bool = True) -> str:
        """Stringify this instance.

        Arguments:
            truncate (bool): Truncate string value to limit length if `True`.
        """

        joined = ", ".join([str(v) for v in self.values.values()])

        if truncate:
            joined = textwrap.shorten(joined, width=64)

        return f"{self.__class__.__name__}({joined})"

    def __repr__(self) -> str:
        return self.stringify()
