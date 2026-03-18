import abc
import io
import typing

from ....platforms import ABI, Platform
from ....utils import find_subclass
from .exceptions import (
    FDIOClosed,
    FDIOInvalid,
    FDIOOutOfFDs,
    FDIOOutOfFileStars,
    FDIOUnknownFile,
)
from .filestar import FileStar
from .io import BasicIO, BytesIO, StderrIO, StdinIO, StdoutIO


class FileDescriptorManager(abc.ABC):
    """Manager for wrangling file descriptors and FILE structs"""

    @property
    @abc.abstractmethod
    def platform(self) -> Platform:
        """Platform this implementations supports"""
        raise NotImplementedError("Abstract method")

    @property
    @abc.abstractmethod
    def abi(self) -> ABI:
        """ABI this implementation supports"""
        raise NotImplementedError("Abstract method")

    _singletons: typing.Dict[typing.Tuple[Platform, ABI], "FileDescriptorManager"] = (
        dict()
    )

    def __init__(self):
        self._fds = dict()
        self._filestars = dict()

        self._files: typing.Dict[
            str, typing.Union[io.BytesIO, typing.Callable[[str, bool, bool], BasicIO]]
        ] = dict()

        # Populate default stdstream file descriptors
        self._fds[0] = StdinIO("/dev/pty/0")
        self._fds[1] = StdoutIO("/dev/pty/0")
        self._fds[2] = StderrIO("/dev/pty/0")

        self.stdin_filestar = 0x46492A00
        self.stdout_filestar = 0x46492A01
        self.stderr_filestar = 0x46492A02

        # Populate default stdstream filestars
        self._filestars[0x46492A00] = FileStar(0, self._fds[0])
        self._filestars[0x46492A01] = FileStar(1, self._fds[1])
        self._filestars[0x46492A02] = FileStar(2, self._fds[2])

    def _get_free_fd(self) -> int:
        for fd in range(0, 1 << 31):
            if fd not in self._fds:
                # Unallocated file descriptor
                return fd

            elif self._fds[fd].closed:
                # File descriptor is closed, and can be reused.
                del self._fds[fd]
                return fd

        # Somehow, we ran out of 2 ** 31 file descriptors.
        raise FDIOOutOfFDs("Out of file descriptors")

    def _get_free_filestar(self) -> int:
        # FILE * pointers are handled as tokens in the range
        # 0x46492A00 - 0x46442AFF

        for i in range(0, 1 << 8):
            filestar = 0x46492A00 | i

            if filestar not in self._filestars:
                return filestar

            elif self._filestars[filestar].closed:
                del self._filestars[filestar]
                return filestar

        raise FDIOOutOfFileStars("Out of file handles")

    def add_file(
        self,
        name: str,
        backing: typing.Union[bytes, typing.Callable[[str, bool, bool], BasicIO]] = b"",
    ):
        """Add a file to the mock file system

        The backing can be specified as bytes,
        or as a factory function that will create a new IO object.
        """
        if isinstance(backing, bytes):
            stream = io.BytesIO(backing)
            self._files[name] = stream
        else:
            self._files[name] = backing

    def get_file(
        self, name: str
    ) -> typing.Union[io.BytesIO, typing.Callable[[str, bool, bool], BasicIO]]:
        if name in self._files:
            return self._files[name]
        raise FDIOUnknownFile(f"{name} is not a file known to the harness")

    def open(
        self,
        name: str,
        readable: bool,
        writable: bool,
        create: bool,
        truncate: bool,
        append: bool,
    ) -> int:
        """Mimic opening a file descriptor

        Arguments:
            name: Name of the file to open
            readable: Whether the file should be readable
            writable: Whether the file should be writable
            create: Whether the file should be created if it doesn't exist.
            truncate: Whether the file should be truncated when opened
            append: Whether the cursor should be set at the end of the file

        Returns:
            an integer file descriptor
        """
        if name not in self._files:
            if not create:
                raise FDIOUnknownFile(
                    f"{name} is not a file known to the harness, and did not specify create"
                )
            else:
                self.add_file(name, b"")

        fd = self._get_free_fd()

        backing = self._files[name]
        stream: BasicIO
        if isinstance(backing, io.BytesIO):
            # File specified as raw bytes.
            # Assume it's a normal file, opened as specified.
            # Assume truncatable and seekable, and not a TTY
            stream = BytesIO(
                name,
                backing,
                readable,
                writable,
                True,
                True,
                False,
            )
        else:
            # File specified as a constructor.
            # Pass in the name and the access mode.
            stream = backing(name, readable, writable)

        if truncate:
            # Requested truncate; truncate the file
            stream.truncate(0)

        if append:
            # Requested append; seek to the back of the file
            stream.seek(0, 2)

        # Bind the file to the integer fd
        self._fds[fd] = stream

        return fd

    def fopen(
        self,
        name: str,
        readable: bool,
        writable: bool,
        create: bool,
        truncate: bool,
        append: bool,
    ) -> int:
        """Open a FILE * file handle.

        This creates both an integer FD, and a FILE * handle
        pointing to the same underlying stream.

        Arguments:
            name: Name of the file to open
            readable: Whether the file should be readable
            writable: Whether the file should be writable
            create: Whether the file should be created if it doesn't exist.
            truncate: Whether the file should be truncated when opened
            append: Whether the cursor should be set at the end of the file

        Returns:
            The FILE * handle assigned to the new stream
        """
        # Open the backing file descriptor
        fd = self.open(name, readable, writable, create, truncate, append)

        try:
            # Allocate a FILE * handle, and wrap the new file stream.
            filestar = self._get_free_filestar()
            self._filestars[filestar] = FileStar(fd, self._fds[fd])
            return filestar
        except FDIOOutOfFileStars as e:
            self._fds[fd].close()
            del self._fds[fd]
            raise e

    def dup(self, old_fd: int, new_fd: typing.Optional[int] = None) -> int:
        """Duplicate a file descriptor

        This will result in two integer fds that reference the same file stream;
        operations performed on one fd will be reflected on the other fd.

        This observes the same behavior as the dup() and dup2()
        system calls:

        - If new_fd is not specified, this will allocate the next available FD.
        - If new_fd is specified:
            - If new_fd is free, it will be assigned to the stream referenced by old_fd
            - If new_fd is already open, it will be reassigned to the stream referenced by old_fd


        Arguments:
            old_fd: Integer file descriptor to duplicate
            new_fd: Integer file descriptor to override, or None to allocate a new fd.

        Returns:
            The new integer fd

        Raises:
            FDIOError: If old_fd is not open, or old_fd or new_fd are not valid fds.
        """
        if new_fd is None:
            new_fd = self._get_free_fd()

        if new_fd < 0 or new_fd >= 1 << 31:
            raise FDIOInvalid(f"Invalid new fd {new_fd}")

        stream = self.get_fd(old_fd).dup()

        self._fds[new_fd] = stream

        return new_fd

    def get_fd(self, fd: int) -> BasicIO:
        """Get the file representaiton by its integer file descriptor

        Arguments:
            fd: The integer file descriptor

        Returns:
            The file representation tied to 'fd'.
        """
        if fd not in self._fds:
            raise FDIOInvalid(f"Unknown fd {fd}")

        if self._fds[fd].closed:
            raise FDIOClosed(f"fd {fd} is closed")

        return self._fds[fd]

    def get_filestar(self, filestar: int) -> BasicIO:
        """Get the file representaiton by its integer handle

        Arguments:
            filestar: The integer file handle

        Returns:
            The file representation tied to 'filestar'.
        """
        if filestar not in self._filestars:
            raise FDIOInvalid(f"Unknown FILE * {hex(filestar)}")
        return self._filestars[filestar]

    def rename(self, old: str, new: str) -> None:
        """Rename a file.

        As of now, there is no actual file tree support;
        the name is merely used as a label.

        Arguments:
            old: The current name of the file
            new: The new name of the file
        """
        if old not in self._files:
            raise FDIOInvalid(f"Unknown file {old}")

        self._files[new] = self._files[old]
        del self._files[old]

    def remove(self, name: str) -> bool:
        """Remove a file

        As of now, there is no actual file tree support;
        the name is merely used as a label.

        Arguments:
            name: Name of the file to remove
        Returns:
            True if model_fs is not set, or if the file was removed
        """
        if name not in self._files:
            return False
        del self._files[name]
        return True

    @classmethod
    def for_platform(cls, platform: Platform, abi: ABI):
        """Get an instance of this class for the desired platform

        NOTE: This isn't a true singleton, and I want it that way.
        Everything that asks for a manager during setup
        should get the same instance,
        but deep-copies of Machines should get their own managers

        Arguments:
            platform: The desired platform
            abi: The desired ABI

        Returns:
            An instance of the manager for the platform
        """
        if (platform, abi) not in cls._singletons:
            cls._singletons[(platform, abi)] = find_subclass(
                cls, lambda x: x.platform == platform and x.abi == abi
            )
        return cls._singletons[(platform, abi)]


__all__ = ["FileDescriptorManager"]
