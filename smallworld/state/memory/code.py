import typing

from ... import emulators
from . import memory


class Executable(memory.RawMemory):
    """An execuable piece of code."""

    entrypoint: typing.Optional[int] = None
    """Entry point address.

    Note:
        This is not used by Emulators - but is available for reference from
        file parsing, if supported.
    """

    def _write_content(
        self, emulator: emulators.Emulator, address: int, content: bytes
    ):
        emulator.write_code(address, content)

    @classmethod
    def from_elf(cls, file: typing.BinaryIO, address: typing.Optional[int] = None):
        """Load an ELF executable from an open file-like object.

        Arguments:
            file: The open file-like object from which to read.
            address: The address where this executable should be loaded.

        Returns:
            An Executable parsed from the given ELF file-like object.
        """
        from .elf import ElfExecutable

        return ElfExecutable(file, user_base=address)

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
