import abc
import logging
import typing

logger = logging.getLogger(__name__)


class Executable:
    """An executable image and metadata storage class.

    Arguments:
        image (bytes): The actual bytes of the executable.
        type (str): Executable format ("blob", "PE", "ELF", etc.)
        arch (str): Architecture ("x86", "arm", etc.)
        mode (str): Architecture mode ("32", "64", etc.)
        base (int): Base address.
        entry (int): Execution entry address.
        exits (list): Exit addresses - used to determine when execution has
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

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(type={self.type}, arch={self.arch}, mode={self.mode}, base={self.base}, entry={self.entry}, exits={self.exits})"


class Executor(metaclass=abc.ABCMeta):
    """A micro executor base class.

    Defines the interface for micro executors.
    """

    @abc.abstractmethod
    def read_register(self, name: str) -> int:
        """Read a value from a register.

        Arguments:
            name (str): The name of the register to read.

        Returns:
            The register value.
        """

        return 0

    @abc.abstractmethod
    def write_register(self, name: str, value: typing.Optional[int]) -> None:
        """Write a value to a register.

        Arguments:
            name (str): The name of the register to write.
            value (int): The value to write.
        """

        pass

    @abc.abstractmethod
    def read_memory(self, address: int, size: int) -> typing.Optional[bytes]:
        """Read memory from a specific address.

        Arguments:
            address (int): The address to read.
            size (bytes): The content of the read.

        Returns:
            {size} bytes read from {address}.
        """

        return b""

    @abc.abstractmethod
    def write_memory(self, address: int, value: typing.Optional[bytes]) -> None:
        """Write memory at a specific address.

        This will allocate memory if necessary.

        Arguments:
            address (int): The address to write.
            value (int): The value to write.
        """

        pass

    @abc.abstractmethod
    def load(self, executable: Executable) -> None:
        """Load a binary for execution.

        Arguments:
            executable (Executable): The executable to load.
        """

        pass

    @abc.abstractmethod
    def run(self) -> None:
        """Start execution."""

        pass

    @abc.abstractmethod
    def step(self) -> bool:
        """Single-step execution.

        Returns:
            `True` if we have reached the program exit point, otherwise `False`.
        """

        pass

    @abc.abstractmethod
    def __repr__(self) -> str:
        """Instance stringifier.

        Implementation requored.
        """

        return ""
