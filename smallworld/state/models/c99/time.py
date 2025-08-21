import os
import time

from ....emulators import Emulator
from ..cstd import ArgumentType, CStdModel
from .utils import _emu_strlen

# NOTE: time_t and clock_t are longs.
# As such, all your 32-bit routers are vulnerable to the 2038 bug.


class TimeModel(CStdModel):
    def time_struct_to_tuple(self, ptr: int, emulator: Emulator):
        # Load the fields out of the struct
        tm_sec = self.read_integer(ptr, ArgumentType.INT, emulator)
        tm_min = self.read_integer(ptr + 0x4, ArgumentType.INT, emulator)
        tm_hour = self.read_integer(ptr + 0x8, ArgumentType.INT, emulator)
        tm_mday = self.read_integer(ptr + 0xC, ArgumentType.INT, emulator)
        tm_mon = self.read_integer(ptr + 0x10, ArgumentType.INT, emulator)
        tm_year = self.read_integer(ptr + 0x14, ArgumentType.INT, emulator)
        tm_wday = self.read_integer(ptr + 0x18, ArgumentType.INT, emulator)
        tm_yday = self.read_integer(ptr + 0x1C, ArgumentType.INT, emulator)
        tm_isdst = self.read_integer(ptr + 0x20, ArgumentType.INT, emulator)

        # Load data into a python struct
        # A few of the fields are represented a bit differently
        out = (
            tm_year + 1900,
            tm_mon + 1,
            tm_mday,
            tm_hour,
            tm_min,
            tm_sec,
            tm_wday - 1,
            tm_yday + 1,
            tm_isdst,
        )

        return out


class Time(TimeModel):
    name = "time"

    # time_t time(time_t *tloc);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.LONG

    def model(self, emulator: Emulator) -> None:
        super().model(emulator)

        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        intval = int(time.time())

        if ptr != 0:
            self.write_integer(ptr, intval, ArgumentType.LONG, emulator)

        self.set_return_value(emulator, intval)


class Localtime(TimeModel):
    name = "localtime"

    # struct tm *localtime(const time_t *timep);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: Emulator) -> None:
        super().model(emulator)
        raise NotImplementedError("localtime returns a pointer to a static struct")


class Gmtime(TimeModel):
    name = "gmtime"

    # struct tm *gmtime(const time_t *timep);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: Emulator) -> None:
        super().model(emulator)
        raise NotImplementedError("gmtime returns a pointer to a static struct")


class Ctime(TimeModel):
    name = "ctime"

    # struct tm *ctime(const time_t *timep);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: Emulator) -> None:
        super().model(emulator)
        raise NotImplementedError("gmtime returns a pointer to a static struct")


class Asctime(TimeModel):
    name = "asctime"

    # char *asctime(const struct tm *tp);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: Emulator) -> None:
        super().model(emulator)
        raise NotImplementedError("asctime returns a pointer to a static buffer")


class Strftime(TimeModel):
    name = "strftime"

    # size_t strftime(char *dst, size_t max, const char *fmt, const struct tm *tp);
    argument_types = [
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.POINTER,
        ArgumentType.POINTER,
    ]
    return_type = ArgumentType.SIZE_T

    def model(self, emulator: Emulator) -> None:
        super().model(emulator)

        dst = self.get_arg1(emulator)
        max = self.get_arg2(emulator)
        fmt = self.get_arg3(emulator)
        ptr = self.get_arg4(emulator)

        assert isinstance(dst, int)
        assert isinstance(max, int)
        assert isinstance(fmt, int)
        assert isinstance(ptr, int)

        fmtlen = _emu_strlen(emulator, fmt)
        fmtbytes = emulator.read_memory(fmt, fmtlen)
        fmtstr = fmtbytes.decode("utf-8")

        timetuple = self.time_struct_to_tuple(ptr, emulator)

        # FIXME: strftime is timezone dependent
        # This is actually something of a pain to handle.  For now, assume UTC.
        old_tz = None
        if "TZ" in os.environ:
            old_tz = os.environ["TZ"]
        os.environ["TZ"] = "UTC"
        time.tzset()

        timestr = time.strftime(fmtstr, timetuple)
        timebytes = timestr.encode("utf-8")
        timebytes += b"\0"

        if old_tz is None:
            del os.environ["TZ"]
        else:
            os.environ["TZ"] = old_tz
        time.tzset()

        if len(timebytes) > max:
            self.set_return_value(emulator, 0)
        else:
            emulator.write_memory(dst, timebytes)
            self.set_return_value(emulator, len(timebytes))


class Difftime(TimeModel):
    name = "difftime"

    # double difftime(time_t time0, time_t time1);
    argument_types = [ArgumentType.LONG, ArgumentType.LONG]
    return_type = ArgumentType.DOUBLE

    def model(self, emulator: Emulator) -> None:
        super().model(emulator)

        time0 = self.get_arg1(emulator)
        time1 = self.get_arg2(emulator)

        assert isinstance(time0, int)
        assert isinstance(time1, int)

        # Times are longs.  Why does this return a double?
        # The world is full of mysteries...
        diff = float(time1 - time0)

        self.set_return_value(emulator, diff)


class Mktime(TimeModel):
    name = "mktime"

    # time_t mktime(struct tm *tp);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.LONG

    def model(self, emulator: Emulator) -> None:
        super().model(emulator)

        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        timetuple = self.time_struct_to_tuple(ptr, emulator)

        # FIXME: mktime is timezone dependent
        # This is actually something of a pain to handle.  For now, assume UTC.
        old_tz = None
        if "TZ" in os.environ:
            old_tz = os.environ["TZ"]
        os.environ["TZ"] = "UTC"
        time.tzset()

        timefloat = time.mktime(timetuple)

        if old_tz is None:
            del os.environ["TZ"]
        else:
            os.environ["TZ"] = old_tz
        time.tzset()

        self.set_return_value(emulator, int(timefloat))


class Clock(TimeModel):
    name = "clock"

    # clock_t clock(void)
    argument_types = []
    return_type = ArgumentType.LONG

    def model(self, emulator: Emulator) -> None:
        super().model(emulator)
        floatval = time.clock_gettime(time.CLOCK_PROCESS_CPUTIME_ID)
        floatval /= time.clock_getres(time.CLOCK_PROCESS_CPUTIME_ID)

        self.set_return_value(emulator, int(floatval))


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
