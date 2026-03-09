from .exceptions import FDIOBadRead
from .io import BasicIO


class FileStar(BasicIO):
    """Representation of a buffered file stream

    This extends an "unbuffered" file descriptor
    by adding support for buffered operations.
    Currently, this only mimics the behavior of ungetc()

    As with C, mixing buffered and unbuffered accesses
    will have very interesting results
    """

    def __init__(self, fileno: int, parent: BasicIO):
        super().__init__(
            parent._name,
            parent._readable,
            parent._writable,
            parent._seekable,
            parent._truncatable,
            parent._isatty,
        )
        self._parent = parent
        self._fileno = fileno
        self._ungetc_buffer: bytes = b""

    @property
    def closed(self) -> bool:
        return self._parent.closed

    def close(self) -> None:
        super().close()
        self._parent.close()

    def fileno(self) -> int:
        return self._fileno

    def on_read(self, n: int) -> bytes:
        # Reading from a filestar needs to handle
        # any data pushed to the buffer by ungetc()
        out = b""
        if len(self._ungetc_buffer) > 0:
            if n < 0:
                out = self._ungetc_buffer
                self._ungetc_buffer = b""
            else:
                out = self._ungetc_buffer[0:n]
                self._ungetc_buffer = self._ungetc_buffer[n:]
                n -= len(out)

        if n != 0:
            out += self._parent.on_read(n)

        return out

    def on_seek(self, offset: int, whence: int) -> int:
        return self._parent.seek(offset, whence)

    def on_tell(self) -> int:
        return self._parent.tell()

    def on_write(self, data: bytes) -> int:
        # Mixing writes with ungetc produces undefined behavior.
        # By observation, this means segfaults;
        # normal software will not require handling this.
        return self._parent.on_write(data)

    def ungetc(self, c: int) -> None:
        if not self._readable:
            raise FDIOBadRead(f"File {self.name} must be readable to use ungetc")
        self._ungetc_buffer = bytes([c]) + self._ungetc_buffer


__all__ = ["FileStar"]
