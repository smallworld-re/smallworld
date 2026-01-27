import io
import sys
import typing

from ...exceptions import ConfigurationError
from ...platforms import ABI, Platform


class FDIOError(Exception):
    """Exception indicating an error case in the file IO model"""

    pass


class FileDescriptor:
    """File Descriptor Representation"""

    def __init__(
        self,
        name: str,
        readable: bool = False,
        writable: bool = False,
        seekable: bool = False,
    ):
        self.name = name

        self.readable = readable
        self.writable = writable
        self.seekable = seekable

        self.ungetc_buf = b""

        self.cursor = 0

        self.eof = False

    @property
    def _backing(self) -> typing.IO:
        # Files aren't pickleable,
        # and anyway we don't want contention on one file object.
        # Instead, dynamically produce the backing file-like,
        # with the understanding that it may need special handling.
        raise FDIOError("File {self.name} has no backing")

    def read(self, size: int, ungetc: bool = False) -> bytes:
        """Read data from this file descriptor

        Arguments:
            size: Number of bytes to read
            ungetc: Set to true to use the 'ungetc' buffer
        """
        if not self.readable:
            raise FDIOError(f"File {self.name} is not readable")

        # NOTE: This integrates support for ungetc.
        # This feature is technically part of FILE * objects;
        # ungetc effectively appends bytes to the beg
        ungetc_data = b""
        if ungetc and len(self.ungetc_buf) > 0:
            if size == -1:
                ungetc_data = self.ungetc_buf
                self.ungetc_buf = b""
            else:
                ungetc_data = self.ungetc_buf[0:size]
                self.ungetc_buf = self.ungetc_buf[size:]

                size -= len(ungetc_data)

        file = self._backing

        if self.seekable:
            # File is seekable; mimic it against the back end.
            file.seek(self.cursor, 0)

        data: typing.Union[str, bytes] = b""
        if size != 0:
            data = file.read(size)
            self.cursor += len(data)
            if len(data) != size:
                print("EOF")
                self.eof = True

        if isinstance(data, str):
            # This is a text file.  Need to encode the result
            assert hasattr(file, "encoding")
            return ungetc_data + data.encode(file.encoding)
        else:
            return ungetc_data + data

    def read_string(self, size: int = -1) -> bytes:
        """Read a newline-terminated string from this file

        Arguments
            size: Maximum number of bytes to read.  Defaults to as many as possible

        Returns:
            String read from file
        """
        out = b""
        size -= 1
        while size != 0:
            c = self.read(1)
            if len(c) < 1:
                break
            out += c

            if c == b"\n":
                break

            if size > 0:
                size -= 1
        out += b"\0"
        return out

    def write(self, data: bytes) -> None:
        """Write data to this file

        Arguments:
            data: Bytes to write to this file
        """
        if not self.writable:
            raise FDIOError(f"File {self.name} is not writable")

        # TODO: Model the effects of ungetc.
        # By observation, mixing writes with ungetc is unsupported;
        # the test program segfaulted when I wran fputc after ungetc

        file = self._backing

        if self.seekable:
            file.seek(self.cursor, 0)

        if hasattr(file, "encoding"):
            # File is a text file.  Need to encode the results
            file.write(data.decode(file.encoding))
        else:
            file.write(data)

        self.cursor += len(data)

    def seek(self, pos: int, whence: int) -> int:
        """Set the cursor for this file

        Arguments:
            pos: Position, possibly relative
            whence: How to interpret 'pos'.  See real implementations for possible values
        """
        if not self.seekable:
            raise FDIOError(f"File {self.name} is not seekable")

        if whence == 0:
            self.cursor = pos
        elif whence == 1:
            self.cursor += pos
        elif whence == 2:
            # Figure out how to find the end of the stream
            raise NotImplementedError()
        else:
            raise FDIOError(f"Unknown 'whence' {whence} when seeking {self.name}")

        return self.cursor

    def ungetc(self, char: int) -> None:
        """Push a character back to the buffer

        In real life, this is only supported by stdio FILE* objects.
        It pushes the character to an internal buffer that's
        read from before the actual stream gets read.

        Its interactions with 'write', 'seek', and readingf from 'cursor'
        are all undefined.

        Arguments:
            char: Character to push
        """
        if not self.readable:
            raise FDIOError(f"File {self.name} is not readable")

        self.ungetc_buf = bytes([char]) + self.ungetc_buf


class BytesFileDescriptor(FileDescriptor):
    """File descriptor backed by a byte string."""

    def __init__(
        self,
        name: str,
        initial: typing.Union[bytes, io.BytesIO] = b"",
        readable: bool = False,
        writable: bool = False,
        seekable: bool = False,
    ):
        super().__init__(name, readable=readable, writable=writable, seekable=seekable)
        if isinstance(initial, bytes):
            initial = io.BytesIO(initial)
        self.backing_io = initial

    @property
    def _backing(self) -> typing.IO:
        return self.backing_io


class StdinFileDescriptor(FileDescriptor):
    """File descriptor backed by host's stdin.

    Read-only, not seekable.
    """

    def __init__(self):
        super().__init__("stdin", readable=True)

    @property
    def _backing(self) -> typing.IO:
        return sys.stdin


class StdoutFileDescriptor(FileDescriptor):
    """File descriptor backed by host's stdout.

    Write-only, not seekable.
    """

    def __init__(self):
        super().__init__("stdout", writable=True)

    @property
    def _backing(self) -> typing.IO:
        return sys.stdout


class StderrFileDescriptor(FileDescriptor):
    """File descriptor backed by host's stderr.

    Write-only, not seekable.
    """

    def __init__(self):
        super().__init__("stderr", writable=True)

    @property
    def _backing(self) -> typing.IO:
        return sys.stderr


class FileDescriptorManager:
    """Manager for wrangling file descriptors

    This handles open, close, and other file descriptor
    manipulation operations.  It also lets you access the file descriptor
    representations themselves.

    This is a unified model that supports C99,
    and is pretty much identical between System V and Windows.

    It also supports an extermely basic filesystem model.
    It's disabled by default, and enabled by setting 'model_fs' to True.
    Its utility is currently extremely limited;
    it has no directory tree or permissions model,
    but it can help for very basic interactions.

    There can absolutely be ABI-specific subclasses.
    """

    _singletons: typing.Dict[typing.Tuple[Platform, ABI], "FileDescriptorManager"] = (
        dict()
    )

    def __init__(self):
        # Enables full FS modeling.
        # By default, this will
        self.model_fs = False

        self._fds = dict()
        self._files = dict()

        # Allocate stdstreams
        # NOTE: This is POSIX-specific
        self._fds[0] = StdinFileDescriptor()
        self._fds[1] = StdoutFileDescriptor()
        self._fds[2] = StderrFileDescriptor()

    def add_file(self, name: str, init: bytes = b"") -> None:
        """Add a file to the manager

        This allows basic support for opening files
        without creating them.

        As of now, there is no actual file tree support;
        whatever string is used as the name is what will match.

        Arguments:
            name: Name or path of the file to place
            init: Initial bytes contained in that file
        """
        if not self.model_fs:
            raise ConfigurationError("Full FS support not enabled.")

        self._files[name] = io.BytesIO(init)

    def get_file(self, name: str) -> io.BytesIO:
        """Get the backing stream behind a file

        Arguments:
            name: The name to look up

        Returns:
            The file-like object storing the byte stream.
        """
        if name in self._files:
            return self._files[name]

        raise KeyError(f"No file named {name}")

    def open(
        self,
        name: str,
        readable: bool,
        writable: bool,
        create: bool,
        truncate: bool,
        append: bool,
        seekable: bool = True,
    ) -> int:
        """Mimic opening a file

        This will behave a bit differently depending
        on whether 'self.model_fs' is set.

        If it's unset, it will create file descriptors blindly,
        and attempting to interact with them will raise exceptions.

        If it's set, it will use the basic file model; see add_file() and get_file().

        As of now, there is no actual file tree support;
        the name is merely used as a label.

        Arguments:
            name: Name of the file to open
            readable: Whether the file should be readable
            writable: Whether the file should be writable
            create: Whether the file should be created if it doesn't exist.
            truncate: Whether the file should be truncated when opened
            append: Whether the cursor should be set at the end of the file
            seekable: Whether the file should be seekable

        Returns:
            An integer file descriptor
        """

        # Limited to 256 file descriptors thanks to shenanigans with FILE * management.
        # If you need more than 256 file descriptors in a micro-execution context,
        # I have many questions.
        for fd in range(0, 1 << 8):
            if fd not in self._fds:
                if self.model_fs:
                    if name not in self._files:
                        if not create:
                            raise FDIOError(
                                f"{name} does not exist, and creation not specified"
                            )
                        self.add_file(name, b"")

                    initial = self._files[name]

                    if truncate:
                        initial.truncate()

                    self._fds[fd] = BytesFileDescriptor(
                        name,
                        initial,
                        readable=readable,
                        writable=writable,
                        seekable=seekable,
                    )

                    if append:
                        self._fds[fd].cursor = len(initial.getvalue())
                else:
                    self._fds[fd] = FileDescriptor(
                        name, readable=readable, writable=writable, seekable=seekable
                    )
                return fd
        raise FDIOError("Ran out of fds")

    def close(self, fd: int) -> None:
        """Close a file

        Arguments:
            fd: Integer file descriptor
        """
        if fd not in self._fds:
            raise FDIOError(f"Unknown fd {fd}")

        del self._fds[fd]

    def get(self, fd: int) -> FileDescriptor:
        """Get the file representaiton by its integer file descriptor

        Arguments:
            fd: The integer file descriptor

        Returns:
            The file representation tied to 'fd'.
        """
        if fd not in self._fds:
            raise FDIOError(f"Unknown fd {fd}")

        return self._fds[fd]

    def rename(self, old: str, new: str) -> None:
        """Rename a file.

        Only available if model_fs is set.

        As of now, there is no actual file tree support;
        the name is merely used as a label.

        Arguments:
            old: The current name of the file
            new: The new name of the file
        """
        if not self.model_fs:
            return

        if old not in self._files:
            raise FDIOError(f"Unknown file {old}")
        self._files[new] = self._files[old]
        del self._files[old]

    def remove(self, name: str) -> bool:
        """Remove a file

        Is a no-op if model_fs is not set.

        As of now, there is no actual file tree support;
        the name is merely used as a label.

        Arguments:
            name: Name of the file to remove
        Returns:
            True if model_fs is not set, or if the file was removed
        """

        if self.model_fs:
            if name in self._files:
                del self._files[name]
                return True
            return False
        else:
            return True

    # Magic number for identifying FILE * pointers created by this API.
    # ASCII for 'FI*'
    #
    # FILE * created by these models don't point to real structs.
    # Rather, they're an encoded form of the file descriptor;
    # the fd number is the LSB, with magic in bytes 1 through 3.
    #
    # On a 64-bit ABI, the upper four bytes should be zero;
    # I don't want to write two models for this.
    #
    # Functions that allow for multiple FILE * structs per FD
    # can go jump in a puddle.
    filestar_magic = 0x47492A

    @classmethod
    def filestar_to_fd(cls, ptr: int) -> int:
        """Convert a FILE* pointer to an integer file descriptor

        This will attempt to detect if the FILE* was actually created
        by SmallWorld's model.  If not, it raises an exception.

        Arguments:
            ptr: The FILE* pointer to decode

        Returns:
            The associated integer file descriptor
        """
        if (ptr >> 8) != cls.filestar_magic:
            raise FDIOError(f"FILE * {hex(ptr)} is not a FILE * created by this model.")

        return ptr & 0xFF

    @classmethod
    def fd_to_filestar(cls, fd: int) -> int:
        """Convert an integer file descriptor to a FILE* pointer

        Arguments:
            fd: The integer file descriptor to encode

        Returns:
            The associated FILE* pointer
        """
        return cls.filestar_magic << 8 | fd

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
            # TODO: Actually implement this when I have multiple implementations
            cls._singletons[(platform, abi)] = cls()
        return cls._singletons[(platform, abi)]
