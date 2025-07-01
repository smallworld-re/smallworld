from .... import emulators
from ..cstd import CStdModel


class Fclose(CStdModel):
    name = "fclose"

    def model(self, emulator: emulators.Emulator) -> None:
        # int fclose(FILE *file);
        raise NotImplementedError()


class Feof(CStdModel):
    name = "feof"

    def model(self, emulator: emulators.Emulator) -> None:
        # int feof(FILE *file);
        raise NotImplementedError()


class Ferror(CStdModel):
    name = "ferror"

    def model(self, emulator: emulators.Emulator) -> None:
        # int ferror(FILE *file);
        raise NotImplementedError()


class Fgetc(CStdModel):
    name = "fgetc"

    def model(self, emulator: emulators.Emulator) -> None:
        # int fgetc(FILE *file);
        raise NotImplementedError()


class Fgets(CStdModel):
    name = "fgets"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *fgets(char *dst, size_t size, FILE *file);
        raise NotImplementedError()


class Fopen(CStdModel):
    name = "fopen"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *fopen(const char *path, const char *mode);
        raise NotImplementedError()


class Fprintf(CStdModel):
    name = "fprintf"

    def model(self, emulator: emulators.Emulator) -> None:
        # int fprintf(FILE *file, const char *fmt, ...);
        raise NotImplementedError()


class Fputc(CStdModel):
    name = "fputc"

    def model(self, emulator: emulators.Emulator) -> None:
        # int fputc(int c, FILE *file);
        raise NotImplementedError()


class Fputs(CStdModel):
    name = "fputs"

    def model(self, emulator: emulators.Emulator) -> None:
        # int fputs(const char *str, FILE *file);
        raise NotImplementedError()


class Fread(CStdModel):
    name = "fread"

    def model(self, emulator: emulators.Emulator) -> None:
        # int fread(void *dst, size_t size, size_t amt, FILE *file);
        raise NotImplementedError()


class Fscanf(CStdModel):
    name = "fscanf"

    def model(self, emulator: emulators.Emulator) -> None:
        # int fscanf(FILE *, const char *fmt, ...);
        raise NotImplementedError()


class Fseek(CStdModel):
    name = "fseek"

    def model(self, emulator: emulators.Emulator) -> None:
        # int fseek(FILE *file, long int offset, int origin);
        raise NotImplementedError()


class Ftell(CStdModel):
    name = "ftell"

    def model(self, emulator: emulators.Emulator) -> None:
        # long ftell(FILE *file);
        raise NotImplementedError()


class Fwrite(CStdModel):
    name = "fwrite"

    def model(self, emulator: emulators.Emulator) -> None:
        # int fwrite(void *src, size_t size, size_t amt, FILE *file);
        raise NotImplementedError()


class Getc(CStdModel):
    name = "getc"

    def model(self, emulator: emulators.Emulator) -> None:
        # int getc(FILE *file);
        raise NotImplementedError()


class Getchar(CStdModel):
    name = "getchar"

    def model(self, emulator: emulators.Emulator) -> None:
        # int getchar(void);
        raise NotImplementedError()


class Printf(CStdModel):
    name = "printf"

    def model(self, emulator: emulators.Emulator) -> None:
        # int printf(const char *fmt, ...);
        raise NotImplementedError()


class Putc(CStdModel):
    name = "putc"

    def model(self, emulator: emulators.Emulator) -> None:
        # int putc(int c, FILE *file);
        raise NotImplementedError()


class Putchar(CStdModel):
    name = "putchar"

    def model(self, emulator: emulators.Emulator) -> None:
        # int putchar(int c);
        raise NotImplementedError()


class Puts(CStdModel):
    name = "puts"

    def model(self, emulator: emulators.Emulator) -> None:
        # int puts(const char *s);
        raise NotImplementedError()


class Remove(CStdModel):
    name = "remove"

    def model(self, emulator: emulators.Emulator) -> None:
        # int remove(const char *path);
        raise NotImplementedError()


class Rename(CStdModel):
    name = "rename"

    def model(self, emulator: emulators.Emulator) -> None:
        # int rename(const char *oldpath, const char *newpath);
        raise NotImplementedError()


class Rewind(CStdModel):
    name = "rewind"

    def model(self, emulator: emulators.Emulator) -> None:
        # void rewind(FILE *file);
        raise NotImplementedError()


class Scanf(CStdModel):
    name = "scanf"

    def model(self, emulator: emulators.Emulator) -> None:
        # int scanf(const char *fmt, ...);
        raise NotImplementedError()


class Snprintf(CStdModel):
    name = "snprintf"

    def model(self, emulator: emulators.Emulator) -> None:
        # int snprintf(char *dst, size_t size, const char *fmt, ...);
        raise NotImplementedError()


class Sprintf(CStdModel):
    name = "sprintf"

    def model(self, emulator: emulators.Emulator) -> None:
        # int sprintf(char *dst, const char *fmt, ...);
        raise NotImplementedError()


class Sscanf(CStdModel):
    name = "sscanf"

    def model(self, emulator: emulators.Emulator) -> None:
        # int sscanf(const char *src, const char *fmt, ...);
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
