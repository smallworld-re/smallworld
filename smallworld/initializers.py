import abc
import logging
import os
import random
import string
import sys
import typing

logger = logging.getLogger(__name__)


class Initializer(metaclass=abc.ABCMeta):
    """Initialization strategy base class.

    Provides semi-random initialization for state values - implementations
    define the strategy.
    """

    @abc.abstractmethod
    def generate(self, length: int) -> bytes:
        """Generate some data.

        Arguments:
            length: the length of data (in bytes) to generate.

        Returns:
            Some data of `length` bytes.
        """

        pass

    def char(self) -> int:
        """Get a char (one bytes) of data.

        Returns:
            An integer representing a single byte of data.
        """

        return int.from_bytes(self.generate(1), "little")

    def short(self) -> int:
        """Get a short (two bytes) of data.

        Returns:
            An integer representing two bytes of data.
        """

        return int.from_bytes(self.generate(2), "little")

    def word(self) -> int:
        """Get a word (four bytes) of data.

        Returns:
            An integer representing four bytes of data.
        """

        return int.from_bytes(self.generate(4), "little")

    def dword(self) -> int:
        """Get a dword (eight bytes) of data.

        Returns:
            An integer representing eight bytes of data.
        """

        return int.from_bytes(self.generate(8), "little")

    def qword(self) -> int:
        """Get a qword (sixteen bytes) of data.

        Returns:
            An integer representing sixteen bytes of data.
        """

        return int.from_bytes(self.generate(16), "little")

    def bytes(self, length: int) -> bytes:
        """Get an arbitrary length bit of data.

        Arguments:
            length: the length of data (in bytes) to generate.

        Returns:
            Some data of `length` bytes.
        """

        return self.generate(length)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}"


class ZeroInitializer(Initializer):
    """Sets values to zero."""

    def generate(self, length: int) -> bytes:
        """Returns zeros."""

        return b"\x00" * length


class OSRandomInitializer(Initializer):
    """Fetches random data from the OS."""

    def __init__(self):
        logger.debug("random seed: unknown (not supported for OS random)")

    def generate(self, length: int) -> bytes:
        return os.urandom(length)


class SeededRandomBaseInitializer(Initializer):
    """Base class for initializers using python `random`."""

    def __init__(self, seed: typing.Optional[int] = None):
        if seed is None:
            # Initialize random so we know the seed.
            seed = random.randrange(sys.maxsize)

        self.seed = seed
        self.random = random.Random(self.seed)

        logger.debug(f"random seed: {random.seed()}")


class RandomUniformInitializer(SeededRandomBaseInitializer):
    """Random, uniformly distributed initialization with a fixed seed."""

    def generate(self, length: int) -> bytes:
        # Slow, but uniform, random, and with a set seed.

        value = []
        for _ in range(length):
            value.append(self.random.randint(0, 255).to_bytes(1, "little"))

        return b"".join(value)


class RandomPrintableInitializer(SeededRandomBaseInitializer):
    """Random, printable initialization with a fixed seed."""

    def generate(self, length: int) -> bytes:
        value = "".join(random.choices(string.printable, k=length))

        return value.encode("utf-8")


__all__ = [
    "Initializer",
    "ZeroInitializer",
    "OSRandomInitializer",
    "RandomUniformInitializer",
    "RandomPrintableInitializer",
]
