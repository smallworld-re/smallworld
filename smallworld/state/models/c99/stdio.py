import random
import string
import typing

from .... import emulators, exceptions
from ....platforms import Byteorder
from ..cstd import ArgumentType, CStdModel
from ..filedesc import FDIOError, FileDescriptorManager
from .fmt_print import parse_printf_format
from .fmt_scan import FileIntake, StringIntake, handle_scanf_format
from .utils import _emu_strlen


class StdioModel(CStdModel):
    def __init__(self, address: int):
        super().__init__(address)
        self._fdmgr = FileDescriptorManager.for_platform(self.platform, self.abi)

    def _parse_mode(self, mode: str) -> typing.Tuple[bool, bool]:
        readable = False
        writable = False
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
        elif mode in ("w+", "w+b"):
            # - Open for reading and writing
            # - Creates if doesn't exist
            # - Truncates if exists
            # - Cursor starts at zero
            readable = True
            writable = True
        elif mode in ("a", "ab"):
            # - Open for writing
            # - Creates if doesn't exist
            # - Cursor starts at end
            writable = True
        elif mode in ("a+", "a+b"):
            # - Open for reading and writing
            # - Creates if doesn't exist
            # - Start is unspecified; glibc does the beginning
            readable = True
            writable = True
        else:
            raise Exception(f"Unknown mode {mode}")

        return (readable, writable)

    def _generate_tmpnam(self):
        # TODO: Doesn't actually test uniqueness
        search = string.ascii_letters + string.ascii_digits

        out = "/tmp/file"
        for i in range(0, 6):
            out += search[random.rand_int(0, len(search))]

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
            fd = self._fdmgr.filestar_to_fd(ptr)
            self._fdmgr.close(fd)
            self.set_return_value(emulator, 0)
        except FDIOError:
            self.set_return_value(emulator, -1)


class Feof(StdioModel):
    name = "feof"

    # int feof(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise NotImplementedError()


class Ferror(StdioModel):
    name = "ferror"

    # int ferror(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise NotImplementedError()


class Clearerr(StdioModel):
    name = "clearerr"

    # void clearerr(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.VOID

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise NotImplementedError()


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
            fd = self._fdmgr.filestar_to_fd(filestar)
            file = self._fdmgr.get(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        data = file.read(1, ungetc=True)

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
            fd = self._fdmgr.filestar_to_fd(filestar)
            file = self._fdmgr.get(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        data = file.read_string(size)
        emulator.write_memory(dst, data)
        self.set_return_value(emulator, len(data))


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

        # FIXME: Not all files are seekable.
        # For now, assume this one is.
        seekable = True

        try:
            readable, writable = self._parse_mode(filemode)
            fd = self._fdmgr.open(
                filepath, readable=readable, writable=writable, seekable=seekable
            )
        except FDIOError:
            self.set_return_value(emulator, 0)
            return

        filestar = self._fdmgr.fd_to_filestar(fd)
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

        # FIXME: Not all files are seekable.
        # For now, assume this one is.
        seekable = True

        # Reset the access mode on the file
        try:
            fd = self._fdmgr.filestar_to_fd(filestar)
            file = self._fdmgr.get(fd)
            readable, writable = self._parse_mode(filemode)
        except FDIOError:
            self.set_return_value(emulator, 0)
            return

        file.readable = readable
        file.writable = writable
        file.seekable = seekable

        # Redirect the file if name is not NULL
        if name != 0:
            len1 = _emu_strlen(emulator, name)
            bytes1 = emulator.read_memory(name, len1)
            filepath = bytes1.decode("utf-8")

            file.name = filepath

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
            fd = self._fdmgr.filestar_to_fd(filestar)
            file = self._fdmgr.get(fd)
        except FDIOError:
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
            fd = self._fdmgr.filestar_to_fd(filestar)
            file = self._fdmgr.get(fd)
        except FDIOError:
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
            fd = self._fdmgr.filestar_to_fd(filestar)
            file = self._fdmgr.get(fd)
        except FDIOError:
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
            fd = self._fdmgr.filestar_to_fd(filestar)
            file = self._fdmgr.get(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        i = 0
        for i in range(0, amt):
            data = file.read(size)
            if len(data) != size:
                file.cursor -= len(data)
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
            fd = self._fdmgr.filestar_to_fd(filestar)
            file = self._fdmgr.get(fd)
        except FDIOError:
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
            fd = self._fdmgr.filestar_to_fd(filestar)
            file = self._fdmgr.get(fd)
        except FDIOError:
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
            fd = self._fdmgr.filestar_to_fd(filestar)
            file = self._fdmgr.get(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)

        self.set_return_value(emulator, file.cursor)


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
            fd = self._fdmgr.filestar_to_fd(filestar)
            file = self._fdmgr.get(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)

        # Okay, this is a pain.
        # fpos_t is platform-specific.
        # On GNU Linux, it's always a struct, and always
        # at least eight bytes.
        # One fieldis the offset.  No idea what the other is.
        #
        # If you read from inside this, I grump at you.

        if self.platform.byteorder == Byteorder.LITTLE:
            data = file.cursor.to_bytes(8, "little")
        elif self.platform.byteorder == Byteorder.BIG:
            data = file.cursor.to_bytes(8, "big")
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
            fd = self._fdmgr.filestar_to_fd(filestar)
            file = self._fdmgr.get(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)

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
            fd = self._fdmgr.filestar_to_fd(filestar)
            file = self._fdmgr.get(fd)

            data = emulator.read_memory(src, size * amt)
            file.write(data)
        except FDIOError:
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
            fd = self._fdmgr.filestar_to_fd(filestar)
            file = self._fdmgr.get(fd)
            file.ungetc(char)
        except FDIOError:
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
        fd = 0

        try:
            file = self._fdmgr.get(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)

        data = file.read(1, ungetc=True)

        self.set_return_value(emulator, data[0])


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

        fd = 1
        try:
            file = self._fdmgr.get(fd)
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
        fd = 1

        try:
            file = self._fdmgr.get(fd)
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
        fd = 1

        try:
            file = self._fdmgr.get(fd)
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

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        self.set_return_value(emulator, 0)


class Rename(StdioModel):
    name = "rename"

    # int rename(const char *oldpath, const char *newpath);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # No file system; just returns true
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        self.set_return_value(emulator, 0)


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
            fd = self._fdmgr.filestar_to_fd(filestar)
            file = self._fdmgr.get(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        file.cursor = 0
        self.set_return_value(emulator, 0)


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
            fd = 0
            file = self._fdmgr.get(fd)
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
            fd = self._fdmgr.open(name, True, True, seekable=True)
        except FDIOError:
            self.set_return_value(emulator, 0)
            return

        filestar = self._fdmgr.fd_to_filestar(fd)
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
            raise NotImplementedError("Using tmpnam internal buffer not supported")

        name = self._generate_tmpnam().encode("utf-8")

        emulator.write_memory(ptr, name)

        self.set_return_value(emulator, ptr)


class Vfprintf(StdioModel):
    name = "vfprintf"

    # int vfprintf(FILE *stream, const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise NotImplementedError()


class Vfscanf(StdioModel):
    name = "vfscanf"

    # int vfscanf(FILE *stream, const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise NotImplementedError()


class Vprintf(StdioModel):
    name = "vprintf"

    # int vprintf(const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise NotImplementedError()


class Vscanf(StdioModel):
    name = "vscanf"

    # int vscanf(const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise NotImplementedError()


class Vsnprintf(StdioModel):
    name = "vsnprintf"

    # int vsprintf(char *str, size_t len, const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER, ArgumentType.SIZE_T, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise NotImplementedError()


class Vsprintf(StdioModel):
    name = "vsprintf"

    # int vsprintf(char *str, const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise NotImplementedError()


class Vsscanf(StdioModel):
    name = "vsprintf"

    # int vsscanf(char *str, const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise NotImplementedError()


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
