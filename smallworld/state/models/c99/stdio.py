import typing

from .... import emulators
from ..cstd import ArgumentType, CStdModel
from ..filedesc import FDIOError, FileDescriptorManager
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


class Fclose(StdioModel):
    name = "fclose"

    # int fclose(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        fd = self._fdmgr.filestar_to_fd(ptr)
        try:
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
        raise NotImplementedError()


class Ferror(StdioModel):
    name = "ferror"

    # int ferror(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Clearerror(StdioModel):
    name = "ferror"

    # void clearerror(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.VOID

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Fflush(StdioModel):
    name = "fflush"

    # int fflush(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Fgetc(StdioModel):
    name = "fgetc"

    # int fgetc(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Fgets(StdioModel):
    name = "fgets"

    # char *fgets(char *dst, size_t size, FILE *file);
    argument_types = [ArgumentType.POINTER, ArgumentType.SIZE_T, ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Fopen(StdioModel):
    name = "fopen"

    # FILE *fopen(const char *path, const char *mode);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
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
        raise NotImplementedError()


class Fprintf(StdioModel):
    name = "fprintf"

    # int fprintf(FILE *file, const char *fmt, ...);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Fputc(StdioModel):
    name = "fputc"

    # int fputc(int c, FILE *file);
    argument_types = [ArgumentType.INT, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Fputs(StdioModel):
    name = "fputs"

    # int fputs(const char *str, FILE *file);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


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
        raise NotImplementedError()


class Fscanf(StdioModel):
    name = "fscanf"

    # int fscanf(FILE *, const char *fmt, ...);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Fseek(StdioModel):
    name = "fseek"

    # int fseek(FILE *file, long int offset, int origin);
    argument_types = [ArgumentType.POINTER, ArgumentType.LONG, ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Ftell(StdioModel):
    name = "ftell"

    # long ftell(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.LONG

    def model(self, emulator: emulators.Emulator) -> None:
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
        raise NotImplementedError()


class Fsetpos(StdioModel):
    name = "fsetpos"

    # int ftell(FILE *file, fpos_t *pos);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


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
        raise NotImplementedError()


class Getc(StdioModel):
    name = "getc"

    # int getc(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        filestar = self.get_arg1(emulator)

        assert isinstance(filestar, int)

        try:
            fd = self._fdmgr.filestar_to_fd(filestar)
            file = self._fdmgr.get(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)

        data = file.read(1)

        self.set_return_value(emulator, data[0])


class Ungetc(StdioModel):
    name = "ungetc"

    # int ungetc(int c, FILE *file);
    argument_types = [ArgumentType.INT, ArgumentType.POINTER]
    return_type = ArgumentType.INT


class Getchar(StdioModel):
    name = "getchar"

    # int getchar(void);
    argument_types = []
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        filestar = self.get_arg1(emulator)

        assert isinstance(filestar, int)

        try:
            fd = self._fdmgr.filestar_to_fd(filestar)
            file = self._fdmgr.get(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)

        data = file.read(1)

        self.set_return_value(emulator, data[0])


class Printf(StdioModel):
    name = "printf"

    # int printf(const char *fmt, ...);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Putc(StdioModel):
    name = "putc"

    # int putc(int c, FILE *file);
    argument_types = [ArgumentType.INT, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        char = self.get_arg1(emulator)
        filestar = self.get_arg2(emulator)

        assert isinstance(char, int)
        assert isinstance(filestar, int)

        try:
            fd = self._fdmgr.filestar_to_fd(filestar)
            file = self._fdmgr.get(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)

        data = file.read(1)

        self.set_return_value(emulator, data[0])


class Putchar(StdioModel):
    name = "putchar"

    # int putchar(int c);
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Puts(StdioModel):
    name = "puts"

    # int puts(const char *s);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Remove(StdioModel):
    name = "remove"

    # int remove(const char *path);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Rename(StdioModel):
    name = "rename"

    # int rename(const char *oldpath, const char *newpath);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Rewind(StdioModel):
    name = "rewind"

    # void rewind(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.VOID

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Scanf(StdioModel):
    name = "scanf"

    # int scanf(const char *fmt, ...);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Snprintf(StdioModel):
    name = "snprintf"

    # int snprintf(char *dst, size_t size, const char *fmt, ...);
    argument_types = [ArgumentType.POINTER, ArgumentType.SIZE_T, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Sprintf(StdioModel):
    name = "sprintf"

    # int sprintf(char *dst, const char *fmt, ...);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Sscanf(StdioModel):
    name = "sscanf"

    # int sscanf(const char *src, const char *fmt, ...);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Tmpfile(StdioModel):
    name = "tmpfile"

    # FILE *tmpfile(void);
    argument_types = []
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Tmpnam(StdioModel):
    name = "tmpnam"

    # char *tmpnam(char *name);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Vfprintf(StdioModel):
    name = "vfprintf"

    # int vfprintf(FILE *stream, const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Vfscanf(StdioModel):
    name = "vfscanf"

    # int vfscanf(FILE *stream, const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Vprintf(StdioModel):
    name = "vprintf"

    # int vprintf(const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Vscanf(StdioModel):
    name = "vscanf"

    # int vscanf(const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Vsnprintf(StdioModel):
    name = "vsnprintf"

    # int vsprintf(char *str, size_t len, const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER, ArgumentType.SIZE_T, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Vsprintf(StdioModel):
    name = "vsprintf"

    # int vsprintf(char *str, const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Vsscanf(StdioModel):
    name = "vsprintf"

    # int vsscanf(char *str, const char *fmt, va_list args);
    # TODO: Figure out how to decode a va_list
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


__all__ = [
    "Clearerror",
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
