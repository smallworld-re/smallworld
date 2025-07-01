from .... import emulators
from ..cstd import CStdModel


class Time(CStdModel):
    name = "time"

    def model(self, emulator: emulators.Emulator) -> None:
        # time_t time(time_t *tloc);
        raise NotImplementedError()


class Localtime(CStdModel):
    name = "localtime"

    def model(self, emulator: emulators.Emulator) -> None:
        # struct tm *localtime(const time_t *timep);
        raise NotImplementedError()


class Gmtime(CStdModel):
    name = "gmtime"

    def model(self, emulator: emulators.Emulator) -> None:
        # struct tm *gmtime(const time_t *timep);
        raise NotImplementedError()


class Ctime(CStdModel):
    name = "ctime"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *ctime(const time_t *timep);
        raise NotImplementedError()


class Asctime(CStdModel):
    name = "asctime"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *asctime(const struct tm *tp);
        raise NotImplementedError()


class Strftime(CStdModel):
    name = "strftime"

    def model(self, emulator: emulators.Emulator) -> None:
        # size_t strftime(char *dst, size_t max, const char *fmt, const struct tm *tp);
        raise NotImplementedError()


class Difftime(CStdModel):
    name = "difftime"

    def model(self, emulator: emulators.Emulator) -> None:
        # double difftime(time_t val1, time_t val2);
        raise NotImplementedError()


class Mktime(CStdModel):
    name = "mktime"

    def model(self, emulator: emulators.Emulator) -> None:
        # time_t mktime(struct tm *tp);
        raise NotImplementedError()


class Clock(CStdModel):
    name = "clock"

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
