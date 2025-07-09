import sys
import typing

from ...platforms import ABI, Platform


class FDIOError(Exception):
    pass


class FileDescriptor:
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

        self.cursor = 0

        # TODO: Add extra state to support FILE * operations.
        # Things like feof and ferror.
        # I don't want to have to add an entire FILE * manager just to track them.

    @property
    def _backing(self) -> typing.IO:
        # Files aren't pickleable,
        # and anyway we don't want contention on one file object.
        # Instead, dynamically produce the backing file-like,
        # with the understanding that it may need special handling.
        raise FDIOError("File {self.name} has no backing")

    def read(self, size: int) -> bytes:
        if not self.readable:
            raise FDIOError(f"File {self.name} is not readable")

        file = self._backing

        if self.seekable:
            # File is seekable; mimic it against the back end.
            file.seek(self.cursor, 0)

        data: typing.Union[str, bytes] = file.read(size)

        if isinstance(data, str):
            # This is a text file.  Need to encode the result
            assert hasattr(file, "encoding")
            return data.encode(file.encoding)
        else:
            return data

    def write(self, data: bytes) -> None:
        if not self.writable:
            raise FDIOError(f"File {self.name} is not writable")

        file = self._backing

        if self.seekable:
            file.seek(self.cursor, 0)

        if hasattr(file, "encoding"):
            # File is a text file.  Need to encode the results
            file.write(data.decode(file.encoding))
        else:
            file.write(data)

    def seek(self, pos: int, whence: int) -> int:
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


class StdinFileDescriptor(FileDescriptor):
    def __init__(self):
        super().__init__("stdin", readable=True)

    @property
    def _backing(self) -> typing.IO:
        return sys.stdin


class StdoutFileDescriptor(FileDescriptor):
    def __init__(self):
        super().__init__("stdout", readable=True)

    @property
    def _backing(self) -> typing.IO:
        return sys.stdout


class StderrFileDescriptor(FileDescriptor):
    def __init__(self):
        super().__init__("stderr", readable=True)

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

    There can absolutely be ABI-specific subclasses.
    """

    _singletons: typing.Dict[
        typing.Tuple[Platform, ABI], "FileDescriptorManager"
    ] = dict()

    def __init__(self):
        self._fds = dict()

        # Allocate stdstreams
        # NOTE: This is POSIX-specific
        self._fds[0] = StdinFileDescriptor()
        self._fds[1] = StdoutFileDescriptor()
        self._fds[2] = StderrFileDescriptor()

    def open(
        self, name: str, readable: bool, writable: bool, seekable: bool = True
    ) -> int:
        # Limited to 256 file descriptors thanks to shenanigans with FILE * management.
        # If you need more than 256 file descriptors in a micro-execution context,
        # I have many questions.
        for fd in range(0, 1 << 8):
            if fd not in self._fds:
                self._fds[fd] = FileDescriptor(
                    name, readable=readable, writable=writable, seekable=seekable
                )
                return fd
        raise FDIOError("Ran out of fds")

    def close(self, fd: int) -> None:
        if fd not in self._fds:
            raise FDIOError(f"Unknown fd {fd}")

        del self._fds[fd]

    def get(self, fd: int) -> FileDescriptor:
        if fd not in self._fds:
            raise FDIOError(f"Unknown fd {fd}")

        return self._fds[fd]

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
        if (ptr >> 8) != cls.filestar_magic:
            raise FDIOError(f"FILE * {hex(ptr)} is not a FILE * created by this model.")

        return ptr & 0xFF

    @classmethod
    def fd_to_filestar(cls, fd: int) -> int:
        return cls.filestar_magic << 8 | fd

    @classmethod
    def for_platform(cls, platform: Platform, abi: ABI):
        # NOTE: This isn't a true singleton, and I want it that way.
        # Everything that asks for a manager during setup
        # should get the same instance,
        # but deep-copies of Machines should get their own managers.
        if (platform, abi) not in cls._singletons:
            # TODO: Actually implement this when I have multiple implementations
            cls._singletons[(platform, abi)] = cls()
        return cls._singletons[(platform, abi)]
