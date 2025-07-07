from .... import emulators
from ..cstd import ArgumentType, CStdModel

# NOTE: time_t and clock_t are longs.
# As such, all your 32-bit routers are vulnerable to the 2038 bug.


class Time(CStdModel):
    name = "time"

    # time_t time(time_t *tloc);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.LONG

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Localtime(CStdModel):
    name = "localtime"

    # struct tm *localtime(const time_t *timep);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Gmtime(CStdModel):
    name = "gmtime"

    # struct tm *gmtime(const time_t *timep);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Ctime(CStdModel):
    name = "ctime"

    # struct tm *ctime(const time_t *timep);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Asctime(CStdModel):
    name = "asctime"

    # char *asctime(const struct tm *tp);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Strftime(CStdModel):
    name = "strftime"

    # size_t strftime(char *dst, size_t max, const char *fmt, const struct tm *tp);
    argument_types = [
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.POINTER,
        ArgumentType.POINTER,
    ]
    return_type = ArgumentType.SIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Difftime(CStdModel):
    name = "difftime"

    # double difftime(time_t val1, time_t val2);
    argument_types = [ArgumentType.LONG, ArgumentType.LONG]
    return_type = ArgumentType.DOUBLE

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Mktime(CStdModel):
    name = "mktime"

    # time_t mktime(struct tm *tp);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.LONG

    def model(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError()


class Clock(CStdModel):
    name = "clock"

    argument_types = []
    return_type = ArgumentType.LONG

    def model(self, emulator: emulators.Emulator) -> None:
        # clock_t clock(void);
        raise NotImplementedError()


__all__ = [
    "Time",
    "Localtime",
    "Gmtime",
    "Ctime",
    "Asctime",
    "Strftime",
    "Difftime",
    "Mktime",
    "Clock",
]
