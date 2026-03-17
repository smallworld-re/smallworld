import logging
import random
import string
import typing

from .... import emulators, exceptions
from ....platforms import Byteorder
from ..cstd import ArgumentType, CStdModel
from ..filedesc import BasicIO, FDIOError, FileDescriptorManager
from .fmt_print import parse_printf_format
from .fmt_scan import FileIntake, StringIntake, handle_scanf_format
from .utils import _emu_strlen

logger = logging.getLogger(__name__)


class StdioModel(CStdModel):
    def __init__(self, address: int):
        super().__init__(address)
        self._fdmgr = FileDescriptorManager.for_platform(self.platform, self.abi)

    def _parse_mode(self, mode: str) -> typing.Tuple[bool, bool, bool, bool, bool]:
        readable = False
        writable = False
        create = False
        truncate = False
        append = True
        if mode in ("r", "rb"):
            # - Open for reading
            # - Fails if doesn't exist
            # - Cursor starts at zero
            readable = True
        elif mode in ("r+", "r+b"):
            # - Open for reading and writing
            # - Fails if doesn't exist
            # - Cursor starts at zero
            readable = True
            writable = True
        elif mode in ("w", "wb"):
            # - Open for writing
            # - Creates if doesn't exist
            # - Truncates if exists
            # - Cursor starts at zero
            writable = True
            create = True
            truncate = True
        elif mode in ("w+", "w+b"):
            # - Open for reading and writing
            # - Creates if doesn't exist
            # - Truncates if exists
            # - Cursor starts at zero
            readable = True
            writable = True
            create = True
            truncate = True
        elif mode in ("a", "ab"):
            # - Open for writing
            # - Creates if doesn't exist
            # - Cursor starts at end
            writable = True
            create = True
            append = True
        elif mode in ("a+", "a+b"):
            # - Open for reading and writing
            # - Creates if doesn't exist
            # - Start is unspecified; glibc does the beginning
            readable = True
            writable = True
            create = True
        else:
            raise FDIOError(f"Unknown mode {mode}")

        return (readable, writable, create, truncate, append)

    def _generate_tmpnam(self):
        # TODO: Doesn't actually test uniqueness
        search = string.ascii_letters + "0123456789"

        out = "/tmp/file"
        for i in range(0, 6):
            out += search[random.randint(0, len(search) - 1)]

        return out


def read_string(file: BasicIO, size: int = -1) -> bytes:
    """Read a newline-terminated string from this file

    Arguments
        file: File from which to read
        size: Maximum number of bytes to read.  Defaults to as many as possible

    Returns:
        String read from file
    """
    out = b""
    size -= 1
    while size != 0:
        c = file.read(1)
        if len(c) < 1:
            break
        out += c

        if c == b"\n":
            break

        if size > 0:
            size -= 1
    out += b"\0"
    return out


class Fclose(StdioModel):
    name = "fclose"

    # int fclose(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        try:
            file = self._fdmgr.get_filestar(ptr)
            file.close()
            self.set_return_value(emulator, 0)
        except FDIOError:
            logger.exception(f"Failed looking up filestar {ptr:x}")
            self.set_return_value(emulator, -1)


class Feof(StdioModel):
    name = "feof"

    # int feof(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        filestar = self.get_arg1(emulator)

        assert isinstance(filestar, int)

        try:
            file = self._fdmgr.get_filestar(filestar)
        except FDIOError:
            logger.exception(f"Failed looking up filestar {filestar:x}")
            self.set_return_value(emulator, -1)
            return

        print(f"EOF: {file.eof}")
        self.set_return_value(emulator, 1 if file.eof else 0)


class Ferror(StdioModel):
    name = "ferror"

    # int ferror(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # We never have errors.
        self.set_return_value(emulator, 0)


class Clearerr(StdioModel):
    name = "clearerr"

    # void clearerr(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.VOID

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        filestar = self.get_arg1(emulator)

        assert isinstance(filestar, int)

        try:
            file = self._fdmgr.get_filestar(filestar)
        except FDIOError:
            logger.exception(f"Failed looking up filestar {filestar:x}")
            self.set_return_value(emulator, -1)
            return

        file.eof = False


class Fflush(StdioModel):
    name = "fflush"

    # int fflush(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # TODO: If you want to model something more interesting here, we can talk.
        self.set_return_value(emulator, 0)


class Fgetc(StdioModel):
    name = "fgetc"

    # int fgetc(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        filestar = self.get_arg1(emulator)

        assert isinstance(filestar, int)

        try:
            file = self._fdmgr.get_filestar(filestar)
        except FDIOError:
            logger.exception(f"Failed looking up filestar {filestar:x}")
            self.set_return_value(emulator, -1)
            return

        try:
            data = file.read(1)
        except FDIOError:
            logger.exception(f"Failed reading from filestar {filestar:x}")
            self.set_return_value(emulator, -1)
            return

        self.set_return_value(emulator, data[0])


class Fgets(StdioModel):
    name = "fgets"

    # char *fgets(char *dst, size_t size, FILE *file);
    argument_types = [ArgumentType.POINTER, ArgumentType.SIZE_T, ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        dst = self.get_arg1(emulator)
        size = self.get_arg2(emulator)
        filestar = self.get_arg3(emulator)

        assert isinstance(dst, int)
        assert isinstance(size, int)
        assert isinstance(filestar, int)

        try:
            file = self._fdmgr.get_filestar(filestar)
        except FDIOError:
            logger.exception(f"Failed looking up filestar {filestar:x}")
            self.set_return_value(emulator, 0)
            return

        data = read_string(file, size)
        emulator.write_memory(dst, data)
        self.set_return_value(emulator, dst)


class Fopen(StdioModel):
    name = "fopen"

    # FILE *fopen(const char *path, const char *mode);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)

        assert isinstance(ptr1, int)
        assert isinstance(ptr2, int)

        len1 = _emu_strlen(emulator, ptr1)
        len2 = _emu_strlen(emulator, ptr2)

        bytes1 = emulator.read_memory(ptr1, len1)
        bytes2 = emulator.read_memory(ptr2, len2)

        filepath = bytes1.decode("utf-8")
        filemode = bytes2.decode("utf-8")

        try:
            readable, writable, create, truncate, append = self._parse_mode(filemode)
            filestar = self._fdmgr.fopen(
                filepath,
                readable,
                writable,
                create,
                truncate,
                append,
            )
        except FDIOError:
            logger.exception(f"Failed opening {filepath} for {filemode}")
            self.set_return_value(emulator, 0)
            return

        self.set_return_value(emulator, filestar)


class Freopen(StdioModel):
    name = "freopen"

    # FILE *freopen(const char *filename, const char *mode, FILE *stream);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        name = self.get_arg1(emulator)
        mode = self.get_arg2(emulator)
        filestar = self.get_arg3(emulator)

        assert isinstance(name, int)
        assert isinstance(mode, int)
        assert isinstance(filestar, int)

        len2 = _emu_strlen(emulator, mode)

        bytes2 = emulator.read_memory(mode, len2)

        filemode = bytes2.decode("utf-8")

        # Reset the access mode on the file
        try:
            file = self._fdmgr.get_filestar(filestar)
            readable, writable, _, _, _ = self._parse_mode(filemode)
        except FDIOError:
            logger.exception(f"Failed looking up filestar {filestar:x}")
            self.set_return_value(emulator, 0)
            return

        # FIXME: This should raise an exception if we're not allowed to reset permissions
        file._readable = readable
        file._writable = writable

        # Redirect the file if name is not NULL
        if name != 0:
            len1 = _emu_strlen(emulator, name)
            bytes1 = emulator.read_memory(name, len1)
            filepath = bytes1.decode("utf-8")

            file._name = filepath

        self.set_return_value(emulator, filestar)


class Fprintf(StdioModel):
    name = "fprintf"

    # int fprintf(FILE *file, const char *fmt, ...);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        filestar = self.get_arg1(emulator)
        fmt_addr = self.get_arg2(emulator)

        assert isinstance(fmt_addr, int)

        fmt_len = _emu_strlen(emulator, fmt_addr)
        fmt_bytes = emulator.read_memory(fmt_addr, fmt_len)
        fmt = fmt_bytes.decode("utf-8")

        output = parse_printf_format(self, fmt, emulator)
        output_bytes = output.encode("utf-8")

        try:
            file = self._fdmgr.get_filestar(filestar)
        except FDIOError:
            logger.exception(f"Failed looking up filestar {filestar:x}")
            self.set_return_value(emulator, -1)
            return

        file.write(output_bytes)

        self.set_return_value(emulator, len(output_bytes))


class Fputc(StdioModel):
    name = "fputc"

    # int fputc(int c, FILE *file);
    argument_types = [ArgumentType.INT, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        char = self.get_arg1(emulator)
        filestar = self.get_arg2(emulator)

        assert isinstance(char, int)
        assert isinstance(filestar, int)

        try:
            file = self._fdmgr.get_filestar(filestar)
        except FDIOError:
            logger.exception(f"Failed looking up filestar {filestar:x}")
            self.set_return_value(emulator, -1)
            return

        file.write(bytes([char]))

        self.set_return_value(emulator, char)


class Fputs(StdioModel):
    name = "fputs"

    # int fputs(const char *str, FILE *file);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        ptr = self.get_arg1(emulator)
        filestar = self.get_arg2(emulator)

        assert isinstance(ptr, int)
        assert isinstance(filestar, int)

        strlen = _emu_strlen(emulator, ptr)
        strbytes = emulator.read_memory(ptr, strlen)

        try:
            file = self._fdmgr.get_filestar(filestar)
        except FDIOError:
            logger.exception(f"Failed looking up filestar {filestar:x}")
            self.set_return_value(emulator, -1)
            return

        file.write(strbytes)

        self.set_return_value(emulator, 0)


class Fread(StdioModel):
    name = "fread"

    # size_t fread(void *dst, size_t size, size_t amt, FILE *file);
    argument_types = [
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.SIZE_T,
        ArgumentType.POINTER,
    ]
    return_type = ArgumentType.SIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        dst = self.get_arg1(emulator)
        size = self.get_arg2(emulator)
        amt = self.get_arg3(emulator)
        filestar = self.get_arg4(emulator)

        assert isinstance(dst, int)
        assert isinstance(size, int)
        assert isinstance(amt, int)
        assert isinstance(filestar, int)

        try:
            file = self._fdmgr.get_filestar(filestar)
        except FDIOError:
            logger.exception(f"Failed looking up filestar {filestar:x}")
            self.set_return_value(emulator, -1)
            return

        i = 0
        for i in range(0, amt):
            data = file.read(size)
            if len(data) != size:
                if file.seekable():
                    file.seek(-len(data), 1)
                break

            emulator.write_memory(dst, data)
            dst += size

        self.set_return_value(emulator, i)


class Fscanf(StdioModel):
    name = "fscanf"

    # int fscanf(FILE *, const char *fmt, ...);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        filestar = self.get_arg1(emulator)
        fmt_addr = self.get_arg2(emulator)

        assert isinstance(filestar, int)
        assert isinstance(fmt_addr, int)

        fmt_len = _emu_strlen(emulator, fmt_addr)
        fmt_bytes = emulator.read_memory(fmt_addr, fmt_len)
        fmt = fmt_bytes.decode("utf-8")

        try:
            file = self._fdmgr.get_filestar(filestar)
        except FDIOError:
            logger.exception(f"Failed looking up filestar {filestar:x}")
            self.set_return_value(emulator, -1)
            return

        intake = FileIntake(file)

        res = handle_scanf_format(self, intake, fmt, emulator)

        self.set_return_value(emulator, res)


class Fseek(StdioModel):
    name = "fseek"

    # int fseek(FILE *file, long int offset, int origin);
    argument_types = [ArgumentType.POINTER, ArgumentType.LONG, ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        filestar = self.get_arg1(emulator)
        offset = self.get_arg2(emulator)
        origin = self.get_arg3(emulator)

        assert isinstance(filestar, int)
        assert isinstance(offset, int)
        assert isinstance(offset, int)

        try:
            file = self._fdmgr.get_filestar(filestar)
        except FDIOError:
            logger.exception(f"Failed looking up filestar {filestar:x}")
            self.set_return_value(emulator, -1)
            return

        pos = file.seek(offset, origin)
        self.set_return_value(emulator, pos)


class Ftell(StdioModel):
    name = "ftell"

    # long ftell(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.LONG

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        filestar = self.get_arg1(emulator)

        assert isinstance(filestar, int)

        try:
            file = self._fdmgr.get_filestar(filestar)
        except FDIOError:
            logger.exception(f"Failed looking up filestar {filestar:x}")
            self.set_return_value(emulator, -1)
            return

        if not file.seekable():
            self.set_return_value(emulator, -1)
        else:
            self.set_return_value(emulator, file.tell())


class Fgetpos(StdioModel):
    name = "fgetpos"

    # int fgetpos(FILE *file, fpos_t *pos);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        filestar = self.get_arg1(emulator)
        ptr = self.get_arg2(emulator)

        assert isinstance(filestar, int)
        assert isinstance(ptr, int)

        try:
            file = self._fdmgr.get_filestar(filestar)
        except FDIOError:
            logger.exception(f"Failed looking up filestar {filestar:x}")
            self.set_return_value(emulator, -1)
            return

        # Okay, this is a pain.
        # fpos_t is platform-specific.
        # On GNU Linux, it's always a struct, and always
        # at least eight bytes.
        # One fieldis the offset.  No idea what the other is.
        #
        # If you read from inside this, I grump at you.

        try:
            raw = file.tell()
        except FDIOError:
            # File is not seekable
            self.set_return_value(emulator, -1)
            return

        if self.platform.byteorder == Byteorder.LITTLE:
            data = raw.to_bytes(8, "little")
        elif self.platform.byteorder == Byteorder.BIG:
            data = raw.to_bytes(8, "big")
        else:
            raise exceptions.ConfigurationError(
                f"Can't encode int for byteorder {self.platform.byteorder}"
            )

        emulator.write_memory(ptr, data)
        self.set_return_value(emulator, 0)


class Fsetpos(StdioModel):
    name = "fsetpos"

    # int ftell(FILE *file, fpos_t *pos);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        filestar = self.get_arg1(emulator)
        ptr = self.get_arg2(emulator)

        assert isinstance(filestar, int)
        assert isinstance(ptr, int)

        try:
            file = self._fdmgr.get_filestar(filestar)
        except FDIOError:
            logger.exception(f"Failed looking up filestar {filestar:x}")
            self.set_return_value(emulator, -1)
            return

        # Okay, this is a pain.
        # fpos_t is platform-specific.
        # On GNU Linux, it's always a struct, and always
        # at least eight bytes.
        # One fieldis the offset.  No idea what the other is.
        #
        # If you read from inside this, I grump at you.

        data = emulator.read_memory(ptr, 8)

        if self.platform.byteorder == Byteorder.LITTLE:
            pos = int.from_bytes(data, "little")
        elif self.platform.byteorder == Byteorder.BIG:
            pos = int.from_bytes(data, "big")
        else:
            raise exceptions.ConfigurationError(
                f"Can't encode int for byteorder {self.platform.byteorder}"
            )
        if not file.seekable():
            self.set_return_value(emulator, -1)
        else:
            file.seek(pos, 0)
            self.set_return_value(emulator, 0)


class Fwrite(StdioModel):
    name = "fwrite"

    # int fwrite(void *src, size_t size, size_t amt, FILE *file);
    argument_types = [
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.SIZE_T,
        ArgumentType.POINTER,
    ]
    return_type = ArgumentType.SIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        src = self.get_arg1(emulator)
        size = self.get_arg2(emulator)
        amt = self.get_arg3(emulator)
        filestar = self.get_arg4(emulator)

        assert isinstance(src, int)
        assert isinstance(size, int)
        assert isinstance(amt, int)
        assert isinstance(filestar, int)

        try:
            file = self._fdmgr.get_filestar(filestar)

            data = emulator.read_memory(src, size * amt)
            file.write(data)
        except FDIOError:
            logger.exception(f"Failed writing to filestar {filestar:x}")
            self.set_return_value(emulator, -1)
            return

        self.set_return_value(emulator, amt)


class Getc(Fgetc):
    name = "getc"

    # NOTE: getc and fgetc behave the same.
    # getc may actually be a macro for fgetc


class Ungetc(StdioModel):
    name = "ungetc"

    # int ungetc(int c, FILE *file);
    argument_types = [ArgumentType.INT, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        char = self.get_arg1(emulator)
        filestar = self.get_arg2(emulator)

        assert isinstance(char, int)
        assert isinstance(char, int)

        try:
            file = self._fdmgr.get_filestar(filestar)
            file.ungetc(char)
        except FDIOError:
            logger.exception(f"Failed ungetc on filestar {filestar:x}")
            self.set_return_value(emulator, -1)
            return

        self.set_return_value(emulator, char)


class Getchar(StdioModel):
    name = "getchar"

    # int getchar(void);
    argument_types = []
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # Use stdin
        # TODO: If someone changes the struct pointed to by stdin, we're in trouble.

        try:
            file = self._fdmgr.get_filestar(self._fdmgr.stdin_filestar)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        data = file.read(1)

        self.set_return_value(emulator, data[0])


class Gets(StdioModel):
    name = "gets"

    # char *fgets(char *dst);
    argument_types = [ArgumentType.POINTER, ArgumentType.SIZE_T, ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        dst = self.get_arg1(emulator)

        assert isinstance(dst, int)

        # Use stdin
        # TODO: If anyone changes the filestar in stdin, we're screwed

        try:
            file = self._fdmgr.get_filestar(self._fdmgr.stdin_filestar)
        except FDIOError:
            self.set_return_value(emulator, 0)
            return

        data = read_string(file)
        emulator.write_memory(dst, data)
        self.set_return_value(emulator, dst)


class Printf(StdioModel):
    name = "printf"

    # int printf(const char *fmt, ...);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fmt_addr = self.get_arg1(emulator)

        assert isinstance(fmt_addr, int)

        fmt_len = _emu_strlen(emulator, fmt_addr)
        fmt_bytes = emulator.read_memory(fmt_addr, fmt_len)
        fmt = fmt_bytes.decode("utf-8")

        output = parse_printf_format(self, fmt, emulator)
        output_bytes = output.encode("utf-8")

        try:
            file = self._fdmgr.get_filestar(self._fdmgr.stdout_filestar)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        file.write(output_bytes)

        self.set_return_value(emulator, len(output_bytes))


class Putc(Fputc):
    name = "putc"

    # NOTE: fputc and putc behave the same.
    # putc may actually be a macro for fputc.


class Putchar(StdioModel):
    name = "putchar"

    # int putchar(int c);
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        char = self.get_arg1(emulator)

        assert isinstance(char, int)

        # Use stdout
        # TODO: If someone changes the FILE * in stdout, we're in trouble.

        try:
            file = self._fdmgr.get_filestar(self._fdmgr.stdout_filestar)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        file.write(bytes([char]))

        self.set_return_value(emulator, char)


class Puts(StdioModel):
    name = "puts"

    # int puts(const char *s);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        size = _emu_strlen(emulator, ptr)

        data = emulator.read_memory(ptr, size)

        # Use stdout
        # TODO: If someone changes the FILE * in stdout, we're in trouble.

        try:
            file = self._fdmgr.get_filestar(self._fdmgr.stdout_filestar)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        file.write(data)
        file.write(b"\n")

        self.set_return_value(emulator, 0)


class Remove(StdioModel):
    name = "remove"

    # int remove(const char *path);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # No file system; just returns true
    imprecise = True

    def __init__(self, address: int):
        self._allow_imprecise = False
        super().__init__(address)

    @property
    def allow_imprecise(self) -> bool:
        return self._allow_imprecise or self._fdmgr.model_fs

    @allow_imprecise.setter
    def allow_imprecise(self, val: bool) -> None:
        self._allow_imprecise = val

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        size = _emu_strlen(emulator, ptr)

        data = emulator.read_memory(ptr, size)

        name = data.decode("utf-8")

        if self._fdmgr.remove(name):
            self.set_return_value(emulator, 0)
        else:
            self.set_return_value(emulator, -1)


class Rename(StdioModel):
    name = "rename"

    # int rename(const char *oldpath, const char *newpath);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # No file system; just returns true
    imprecise = True

    def __init__(self, address: int):
        self._allow_imprecise = False
        super().__init__(address)

    @property
    def allow_imprecise(self) -> bool:
        return self._allow_imprecise or self._fdmgr.model_fs

    @allow_imprecise.setter
    def allow_imprecise(self, val: bool) -> None:
        self._allow_imprecise = val

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        oldptr = self.get_arg1(emulator)
        newptr = self.get_arg2(emulator)

        assert isinstance(oldptr, int)
        assert isinstance(newptr, int)

        oldsize = _emu_strlen(emulator, oldptr)
        newsize = _emu_strlen(emulator, newptr)

        olddata = emulator.read_memory(oldptr, oldsize)
        newdata = emulator.read_memory(newptr, newsize)

        old = olddata.decode("utf-8")
        new = newdata.decode("utf-8")

        try:
            self._fdmgr.rename(old, new)
            self.set_return_value(emulator, 0)
        except FDIOError:
            self.set_return_value(emulator, -1)


class Rewind(StdioModel):
    name = "rewind"

    # void rewind(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.VOID

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        filestar = self.get_arg1(emulator)

        assert isinstance(filestar, int)

        try:
            file = self._fdmgr.get_filestar(filestar)
        except FDIOError:
            return

        file.seek(0, 0)


class Scanf(StdioModel):
    name = "scanf"

    # int scanf(const char *fmt, ...);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fmt_addr = self.get_arg1(emulator)

        assert isinstance(fmt_addr, int)

        fmt_len = _emu_strlen(emulator, fmt_addr)
        fmt_bytes = emulator.read_memory(fmt_addr, fmt_len)
        fmt = fmt_bytes.decode("utf-8")

        try:
            file = self._fdmgr.get_filestar(self._fdmgr.stdin_filestar)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        intake = FileIntake(file)

        res = handle_scanf_format(self, intake, fmt, emulator)

        self.set_return_value(emulator, res)


class Snprintf(StdioModel):
    name = "snprintf"

    # int snprintf(char *dst, size_t size, const char *fmt, ...);
    argument_types = [ArgumentType.POINTER, ArgumentType.SIZE_T, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        buf_addr = self.get_arg1(emulator)
        size = self.get_arg2(emulator)
        fmt_addr = self.get_arg3(emulator)

        assert isinstance(buf_addr, int)
        assert isinstance(size, int)
        assert isinstance(fmt_addr, int)

        fmt_len = _emu_strlen(emulator, fmt_addr)
        fmt_bytes = emulator.read_memory(fmt_addr, fmt_len)
        fmt = fmt_bytes.decode("utf-8")

        output = parse_printf_format(self, fmt, emulator)
        output_bytes = output.encode("utf-8")
        output_bytes += b"\0"

        trunc_bytes = output_bytes
        if len(trunc_bytes) > size:
            trunc_bytes = trunc_bytes[: size - 1]
            trunc_bytes += b"\0"

        if buf_addr != 0:
            emulator.write_memory(buf_addr, output_bytes)

        self.set_return_value(emulator, len(output_bytes) - 1)


class Sprintf(StdioModel):
    name = "sprintf"

    # int sprintf(char *dst, const char *fmt, ...);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        buf_addr = self.get_arg1(emulator)
        fmt_addr = self.get_arg2(emulator)

        assert isinstance(buf_addr, int)
        assert isinstance(fmt_addr, int)

        fmt_len = _emu_strlen(emulator, fmt_addr)
        fmt_bytes = emulator.read_memory(fmt_addr, fmt_len)
        fmt = fmt_bytes.decode("utf-8")

        output = parse_printf_format(self, fmt, emulator)
        output_bytes = output.encode("utf-8")
        output_bytes += b"\0"

        if buf_addr != 0:
            emulator.write_memory(buf_addr, output_bytes)

        self.set_return_value(emulator, len(output_bytes) - 1)


class Sscanf(StdioModel):
    name = "sscanf"

    # int sscanf(const char *src, const char *fmt, ...);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        src_addr = self.get_arg1(emulator)
        fmt_addr = self.get_arg2(emulator)

        assert isinstance(src_addr, int)
        assert isinstance(fmt_addr, int)

        fmt_len = _emu_strlen(emulator, fmt_addr)
        fmt_bytes = emulator.read_memory(fmt_addr, fmt_len)
        fmt = fmt_bytes.decode("utf-8")

        intake = StringIntake(src_addr, emulator)

        res = handle_scanf_format(self, intake, fmt, emulator)

        self.set_return_value(emulator, res)


class Tmpfile(StdioModel):
    name = "tmpfile"

    # FILE *tmpfile(void);
    argument_types = []
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        name = self._generate_tmpnam()

        try:
            filestar = self._fdmgr.fopen(
                name,
                True,
                True,
                True,
                False,
                False,
            )
        except FDIOError:
            self.set_return_value(emulator, 0)
            return

        self.set_return_value(emulator, filestar)


class Tmpnam(StdioModel):
    name = "tmpnam"

    # char *tmpnam(char *name);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        if ptr == 0:
            raise exceptions.UnsupportedModelError(
                "Using tmpnam internal buffer not supported"
            )

        name = self._generate_tmpnam().encode("utf-8")

        emulator.write_memory(ptr, name)

        self.set_return_value(emulator, ptr)


class Vfprintf(StdioModel):
    name = "vfprintf"

    # int vfprintf(FILE *stream, const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # No model for va_list
    unsupported = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise exceptions.UnsupportedModelError(f"{self.name} requires va_list support")


class Vfscanf(StdioModel):
    name = "vfscanf"

    # int vfscanf(FILE *stream, const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # No model for va_list
    unsupported = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise exceptions.UnsupportedModelError(f"{self.name} requires va_list support")


class Vprintf(StdioModel):
    name = "vprintf"

    # int vprintf(const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # No model for va_list
    unsupported = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise exceptions.UnsupportedModelError(f"{self.name} requires va_list support")


class Vscanf(StdioModel):
    name = "vscanf"

    # int vscanf(const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # No model for va_list
    unsupported = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise exceptions.UnsupportedModelError(f"{self.name} requires va_list support")


class Vsnprintf(StdioModel):
    name = "vsnprintf"

    # int vsprintf(char *str, size_t len, const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER, ArgumentType.SIZE_T, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # No model for va_list
    unsupported = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise exceptions.UnsupportedModelError(f"{self.name} requires va_list support")


class Vsprintf(StdioModel):
    name = "vsprintf"

    # int vsprintf(char *str, const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # No model for va_list
    unsupported = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise exceptions.UnsupportedModelError(f"{self.name} requires va_list support")


class Vsscanf(StdioModel):
    name = "vsprintf"

    # int vsscanf(char *str, const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # No model for va_list
    unsupported = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise exceptions.UnsupportedModelError(f"{self.name} requires va_list support")


__all__ = [
    "Clearerr",
    "Fclose",
    "Feof",
    "Ferror",
    "Fflush",
    "Fgetc",
    "Fgetpos",
    "Fgets",
    "Fopen",
    "Fprintf",
    "Fputc",
    "Fputs",
    "Fread",
    "Freopen",
    "Fscanf",
    "Fseek",
    "Fsetpos",
    "Ftell",
    "Fwrite",
    "Getc",
    "Getchar",
    "Gets",
    "Printf",
    "Putc",
    "Putchar",
    "Puts",
    "Remove",
    "Rename",
    "Rewind",
    "Scanf",
    "Snprintf",
    "Sprintf",
    "Sscanf",
    "Tmpfile",
    "Tmpnam",
    "Ungetc",
    "Vfprintf",
    "Vfscanf",
    "Vprintf",
    "Vscanf",
    "Vsnprintf",
    "Vsprintf",
    "Vsscanf",
]
