from .... import emulators
from ..cstd import ArgumentType, CStdModel


class Fclose(CStdModel):
    name = "fclose"

    # int fclose(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Feof(CStdModel):
    name = "feof"

    # int feof(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Ferror(CStdModel):
    name = "ferror"

    # int ferror(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Fgetc(CStdModel):
    name = "fgetc"

    # int fgetc(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Fgets(CStdModel):
    name = "fgets"

    # char *fgets(char *dst, size_t size, FILE *file);
    argument_types = [ArgumentType.POINTER, ArgumentType.SIZE_T, ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Fopen(CStdModel):
    name = "fopen"

    # char *fopen(const char *path, const char *mode);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Fprintf(CStdModel):
    name = "fprintf"

    # int fprintf(FILE *file, const char *fmt, ...);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Fputc(CStdModel):
    name = "fputc"

    # int fputc(int c, FILE *file);
    argument_types = [ArgumentType.INT, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Fputs(CStdModel):
    name = "fputs"

    # int fputs(const char *str, FILE *file);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Fread(CStdModel):
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


class Fscanf(CStdModel):
    name = "fscanf"

    # int fscanf(FILE *, const char *fmt, ...);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Fseek(CStdModel):
    name = "fseek"

    # int fseek(FILE *file, long int offset, int origin);
    argument_types = [ArgumentType.POINTER, ArgumentType.LONG, ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Ftell(CStdModel):
    name = "ftell"

    # long ftell(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.LONG

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Fwrite(CStdModel):
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


class Getc(CStdModel):
    name = "getc"

    # int getc(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Getchar(CStdModel):
    name = "getchar"

    # int getchar(void);
    argument_types = []
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Printf(CStdModel):
    name = "printf"

    # int printf(const char *fmt, ...);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Putc(CStdModel):
    name = "putc"

    # int putc(int c, FILE *file);
    argument_types = [ArgumentType.INT, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Putchar(CStdModel):
    name = "putchar"

    # int putchar(int c);
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Puts(CStdModel):
    name = "puts"

    # int puts(const char *s);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Remove(CStdModel):
    name = "remove"

    # int remove(const char *path);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Rename(CStdModel):
    name = "rename"

    # int rename(const char *oldpath, const char *newpath);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Rewind(CStdModel):
    name = "rewind"

    # void rewind(FILE *file);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.VOID

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Scanf(CStdModel):
    name = "scanf"

    # int scanf(const char *fmt, ...);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Snprintf(CStdModel):
    name = "snprintf"

    # int snprintf(char *dst, size_t size, const char *fmt, ...);
    argument_types = [ArgumentType.POINTER, ArgumentType.SIZE_T, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Sprintf(CStdModel):
    name = "sprintf"

    # int sprintf(char *dst, const char *fmt, ...);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Sscanf(CStdModel):
    name = "sscanf"

    # int sscanf(const char *src, const char *fmt, ...);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


__all__ = [
    "Fclose",
    "Feof",
    "Ferror",
    "Fgetc",
    "Fgets",
    "Fopen",
    "Fprintf",
    "Fputc",
    "Fputs",
    "Fread",
    "Fscanf",
    "Fseek",
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
]
