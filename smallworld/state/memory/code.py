import os
import typing

from ... import state
from . import memory

class Executable(memory.Memory):
    """An execuable piece of code."""

    entrypoint: typing.Optional[int] = None
    """Entry point address.

    Note:
        This is not used by Emulators - but is available for reference from
        file parsing, if supported.
    """

    @classmethod
    def from_bytes(cls, bytes: bytes, address: int):
        """Load an executable from a byte array.

        Arguments:
            bytes: The bytes of the executable.
            address: The address where this executable should be loaded.

        Returns:
            An Executable parsed from the given bytes.
        """

        executable = cls(address=address, size=len(bytes))
        executable[0] = bytes

        return executable

    @classmethod
    def from_file(cls, file: typing.BinaryIO, address: int):
        """Load an executable from an open file-like object.

        Arguments:
            file: The open file-like object from which to read.
            address: The address where this executable should be loaded.

        Returns:
            An Executable parsed from the given file-like object.
        """

        data, size = file.read(), file.tell()

        executable = cls(address=address, size=size)
        executable[0] = state.BytesValue(data, "code")

        return executable

    @classmethod
    def from_filepath(cls, path: str, address: int):
        """Load an executable from a file path.

        Arguments:
            path: The path to the file to load.
            address: The address where this executable should be loaded.

        Returns:
            An Executable parsed from the given file path.
        """

        path = os.path.abspath(os.path.expanduser(path))

        with open(path, "rb") as f:
            return cls.from_file(file=f, address=address)

    @classmethod
    def from_elf(cls, file: typing.BinaryIO):
        """Load an ELF executable from an open file-like object.

        Arguments:
            file: The open file-like object from which to read.
            address: The address where this executable should be loaded.

        Returns:
            An Executable parsed from the given ELF file-like object.
        """

        raise NotImplementedError("ELF parsing not yet implemented")

    @classmethod
    def from_pe(cls, file: typing.BinaryIO):
        """Load an PE executable from an open file-like object.

        Arguments:
            file: The open file-like object from which to read.
            address: The address where this executable should be loaded.

        Returns:
            An Executable parsed from the given PE file-like object.
        """
        raise NotImplementedError("PE parsing not yet implemented")


__all__ = ["Executable"]
