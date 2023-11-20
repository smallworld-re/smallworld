import abc
import typing
import logging


logger = logging.getLogger(__name__)


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
    def load(self, image: bytes, base: int) -> None:
        """Load a binary for execution.

        Arguments:
            image (bytes): The raw executable to load.
            base (int): The base address at which to load the executable.
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
