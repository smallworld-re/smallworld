# from .... import exceptions
from .... import emulators
from ..cstd import CStdModel


class FClose(CStdModel):
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


class FGetc(CStdModel):
    name = "fgetc"

    def model(self, emulator: emulators.Emulator) -> None:
        # int fgetc(FILE *file);
        raise NotImplementedError()


class FGets(CStdModel):
    name = "fgets"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *fgets(char *dst, size_t size, FILE *file);
        raise NotImplementedError()


class FOpen(CStdModel):
    name = "fopen"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *fopen(const char *path, const char *mode);
        raise NotImplementedError()


class FPrintf(CStdModel):
    name = "fprintf"

    def model(self, emulator: emulators.Emulator) -> None:
        # int fprintf(FILE *file, const char *fmt, ...);
        # Variadic functions can jump in a puddle.
        raise NotImplementedError()


class FPutc(CStdModel):
    name = "fputc"

    def model(self, emulator: emulators.Emulator) -> None:
        # int fputc(int c, FILE *file);
        raise NotImplementedError()


class FPuts(CStdModel):
    name = "fputs"

    def model(self, emulator: emulators.Emulator) -> None:
        # int fputs(const char *str, FILE *file);
        raise NotImplementedError()
