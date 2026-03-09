import abc
import copy
import io
import sys
import typing

from .exceptions import (
    FDIOBadRead,
    FDIOBadSeek,
    FDIOBadTruncate,
    FDIOBadWrite,
    FDIOClosed,
)


class BasicIO:
    """Callback-driven file stream model

    This allows harness authors to build models
    of complex files by directly overriding the file stream interface.

    By default, this will represent a file that's not readable, writable, or seekable.
    To enable each of the features, you should override the following methods:

    - readable: on_read
    - writable: on_write
    - seekable: on_seek, on_tell
    - writable and truncatable: on_truncate

    You may also want to override close() and flush() for modelling purposes.

    If your file stores some kind of backing information,
    you will need to override dup() to create a clone of the IO stream
    that shares backing data with the original.
    """

    def __init__(
        self,
        name: str,
        readable: bool,
        writable: bool,
        seekable: bool,
        truncatable: bool,
        isatty: bool,
    ):
        self._name = name
        self._readable = readable
        self._writable = writable
        self._seekable = seekable
        self._truncatable = truncatable
        self._isatty = isatty

        self._closed = False

    def on_read(self, n: int) -> bytes:
        """Callback for handling read operations.

        Doesn't need to be implemented if the file isn't readable;
        this will be handled by the implementation of read().

        Arguments:
            n: Number of bytes to read; -1 to read entire stream

        Returns:
            The bytes read from the model
        """
        raise NotImplementedError("File {self.name} does not support reading")

    def on_seek(self, offset: int, whence: int) -> int:
        """Callback for handling seek operations.

        Doesn't need to be implemented if the file isn't seekable;
        this will be handled by the implementation of seek().

        NOTE: "whence" is a bit OS-dependent.
        POSIX defines the following values:

        - 0: offset is an absolute offset into the file
        - 1: offset is relative to the current cursor offset
        - 2: offset is relative to the end of the file.

        If your system is weird, there may be more.

        Arguments:
            offset: Offset to which you want to seek
            whence: Enum encoding how to interpret 'offset'

        Returns:
            The new cursor position
        """
        raise NotImplementedError(f"File {self.name} does not support seeking")

    def on_tell(self) -> int:
        """Callback for handling tell operations.

        Doesn't need to be implemented if the file isn't seekable;
        this will be handled by the implementation of tell().

        Returns:
            The current cursor position
        """
        raise NotImplementedError(f"File {self.name} does not support seeking")

    def on_truncate(self, size: int) -> int:
        """Callback for handling truncate operations.

        Doesn't need to be implemented if the file isn't writable or truncatable;
        this will be handled by the implementation of truncate().

        Arguments:
            size: The new size of the file
        """
        raise NotImplementedError(f"File {self.name} does not support writing")

    def on_write(self, data: bytes) -> int:
        """Callback for handling write operations

        Doesn't need to be implemented if the file isn't writable;
        this will be handled by the implementation of write().

        Arguments:
            data: The data to write

        Returns:
            The number of bytes successfully written
        """
        raise NotImplementedError(f"File {self.name} does not support writing")

    def dup(self) -> "BasicIO":
        return copy.deepcopy(self)

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def mode(self) -> str:
        raise NotImplementedError("Property 'mode' not supported")

    @property
    def name(self) -> str:
        return self._name

    def __enter__(self) -> typing.BinaryIO:
        raise NotImplementedError("__enter__ not supported")

    def __exit__(self, type, value, traceback) -> None:
        raise NotImplementedError("__exit__ not supported")

    def close(self) -> None:
        if self.closed:
            raise FDIOClosed(f"File {self.name} is closed")

        self._closed = True

    def fileno(self) -> int:
        raise NotImplementedError("fileno not supported")

    def flush(self) -> None:
        if self.closed:
            raise FDIOClosed(f"File {self.name} is closed")

        pass

    def isatty(self) -> bool:
        if self.closed:
            raise FDIOClosed(f"File {self.name} is closed")

        return self._isatty

    def read(self, n: int = -1) -> bytes:
        if self.closed:
            raise FDIOClosed(f"File {self.name} is closed")

        if not self._readable:
            raise FDIOBadRead(f"File {self.name} is not readable")

        return self.on_read(n)

    def readable(self) -> bool:
        if self.closed:
            raise FDIOClosed(f"File {self.name} is closed")

        return self._readable

    def readline(self, limit: int = -1) -> bytes:
        raise NotImplementedError("readline not supported")

    def readlines(self, hint: int = -1) -> typing.List[bytes]:
        raise NotImplementedError("readlines not supported")

    def seek(self, offset: int, whence: int = 0) -> int:
        if self.closed:
            raise FDIOClosed(f"File {self.name} is closed")

        if not self._seekable:
            raise FDIOBadSeek(f"File {self.name} is not seekable")

        return self.on_seek(offset, whence)

    def seekable(self) -> bool:
        if self.closed:
            raise FDIOClosed(f"File {self.name} is closed")

        return True

    def tell(self) -> int:
        if self.closed:
            raise FDIOClosed(f"File {self.name} is closed")

        if not self._seekable:
            raise FDIOBadSeek(f"File {self.name} is not seekable")

        return self.on_tell()

    def truncate(self, size: typing.Optional[int] = None) -> int:
        if self.closed:
            raise FDIOClosed(f"File {self.name} is closed")

        if not self._writable:
            raise FDIOBadWrite(f"File {self.name} must be writable to truncate")

        if not self._truncatable:
            raise FDIOBadTruncate(f"File {self.name} is not truncatable")

        # Python allows you to truncate to the current cursor value
        # by specifying None as the size
        if size is None:
            size = self.tell()

        return self.on_truncate(size)

    def writable(self) -> bool:
        if self.closed:
            raise FDIOClosed(f"File {self.name} is closed")

        return self._writable

    def write(self, data: bytes) -> int:
        if self.closed:
            raise FDIOClosed(f"File {self.name} is closed")

        if not self._writable:
            raise FDIOBadWrite(f"File {self.name} is not writable")

        return self.on_write(data)

    def writelines(self, lines: typing.Iterable[bytes], /) -> None:
        raise NotImplementedError("writelines not supported")


class BytesIO(BasicIO):
    """Byte-backed file IO stream object.

    This adds a few features to Python's BytesIO,
    and makes it easier to share file state between handles.
    """

    def __init__(
        self,
        name: str,
        data: io.BytesIO,
        readable: bool,
        writable: bool,
        seekable: bool,
        truncatable: bool,
        isatty: bool,
        cursor: int = 0,
    ):
        super().__init__(name, readable, writable, seekable, truncatable, isatty)
        self._parent = data
        self._cursor = cursor

    def on_read(self, n: int) -> bytes:
        self._parent.seek(self._cursor, 0)
        return self._parent.read(n)

    def on_seek(self, offset: int, whence: int) -> int:
        if whence == 0:
            # SEEK_SET: offset is an absolute position
            self._cursor = offset
        elif whence == 1:
            # SEEK_CUR: offset is relative to current cursor
            self._cursor += offset
        elif whence == 2:
            # SEEK_END:
            self._cursor = len(self._parent.getvalue()) + offset
        else:
            raise ValueError(f"Unknown whence {whence}")

        return self._cursor

    def on_tell(self) -> int:
        return self._cursor

    def on_truncate(self, size: int) -> int:
        return self._parent.truncate(size)

    def on_write(self, data: bytes) -> int:
        self._parent.seek(self._cursor, 0)
        return self._parent.write(data)

    def dup(self) -> BasicIO:
        return BytesIO(
            self._name,
            self._parent,
            self._readable,
            self._writable,
            self._seekable,
            self._truncatable,
            self._isatty,
            self._cursor,
        )


class StdStreamIO(BasicIO, abc.ABC):
    """Pickleable wrapper around host's stdstreams

    File streams can't be deepcopied by Python,
    but we know where to find the stdstream handles, so we can generate them as needed.

    Helps that they are not seekable or truncatable,
    so we don't need to worry too much about maintaining state.
    """

    @property
    @abc.abstractmethod
    def _stream(self) -> typing.IO:
        raise NotImplementedError("abstract method")

    def on_read(self, n: int) -> bytes:
        # In Python, stdstreams are text streams.
        # Need to convert the output to bytes.
        stream = self._stream
        data = stream.read(n)

        assert hasattr(stream, "encoding")
        return data.encode(stream.encoding)

    def on_write(self, data: bytes) -> int:
        # In Python, stdstreams are text streams.
        # Need to convert the input to a string
        # This can cause problems if someone is using a binary protocol over stdstreams.
        stream = self._stream
        assert hasattr(stream, "encoding")
        return stream.write(data.decode(stream.encoding))


class StdinIO(StdStreamIO):
    """Pickleable wrapper around host's stdin."""

    def __init__(self, name: str):
        super().__init__(name, True, False, False, False, True)

    @property
    def _stream(self) -> typing.IO:
        return sys.stdin


class StdoutIO(StdStreamIO):
    """Pickleable wrapper around host's stdout"""

    def __init__(self, name: str):
        super().__init__(name, True, False, False, False, True)

    @property
    def _stream(self) -> typing.IO:
        return sys.stdout


class StderrIO(StdStreamIO):
    """Pickleable wrapper around host's stderr"""

    def __init__(self, name: str):
        super().__init__(name, True, False, False, False, True)

    @property
    def _stream(self) -> typing.IO:
        return sys.stderr


__all__ = [
    "BasicIO",
    "BytesIO",
    "StdinIO",
    "StdoutIO",
    "StderrIO",
]
