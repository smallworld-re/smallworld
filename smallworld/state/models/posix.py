import abc
import logging
import random

from ... import emulators
from .model import Model

logger = logging.getLogger(__name__)

######################################################
# This stuff is private. Dont' add it to __all__     #
######################################################


MAX_STRLEN = 0x10000


# obtain addr of emulator heap memory of this size
# NB: this will map new pages into emulator as needed
def _emu_alloc(emulator: emulators.Emulator, size: int) -> int:
    address = 0x10000
    memory_map = emulator.get_memory_map()
    if len(memory_map) > 0:
        address = memory_map[-1][1]
    emulator.map_memory(address, size)
    return address


def _emu_calloc(emulator: emulators.Emulator, size: int) -> int:
    addr = _emu_alloc(emulator, size)
    emulator.write_memory(addr, b"\0" * size)
    return addr


def _emu_strlen_n(emulator: emulators.Emulator, addr: int, n: int) -> int:
    sl = 0
    while sl <= n:
        b_opt = emulator.read_memory(addr + sl, 1)
        if b_opt is not None:
            b = b_opt[0]
            if b == 0:
                break
            sl += 1
        else:
            assert b_opt is not None
    return sl


def _emu_strlen(emulator: emulators.Emulator, addr: int) -> int:
    return _emu_strlen_n(emulator, addr, MAX_STRLEN)


def _emu_memcpy(emulator: emulators.Emulator, dst: int, src: int, n: int) -> None:
    src_bytes = emulator.read_memory(src, n)
    emulator.write_memory(dst, src_bytes)


def _emu_strncpy(
    emulator: emulators.Emulator, dst: int, src: int, n: int, is_strncpy: bool
) -> None:
    if n == 0:
        return
    if emulator.read_memory(src, 1) is None:
        logger.debug("MEM not available in strncpy read @ {src:x}")
    elif emulator.read_memory(dst, 1) is None:
        logger.debug("MEM not available in strncpy write @ {dst:x}")
    else:
        # at least a byte is available at both src and dst
        # find length of src (not to exceed l)
        l2 = _emu_strlen_n(emulator, src, n)
        l3 = min(n, l2)
        if l3 > 0:
            # read the src string and copy to dst
            src_bytes = emulator.read_memory(src, l3)
            emulator.write_memory(dst, src_bytes)
            if is_strncpy and l3 < n:
                # if src string is less than n bytes then, according to man page
                # strncpy copies 0s to get to n bytes
                emulator.write_memory(dst + l3, b"\0" * (n - l3))


def _emu_strncat(emulator: emulators.Emulator, dst: int, src: int, n: int) -> None:
    if n == 0:
        return
    if emulator.read_memory(src, 1) is None:
        logger.debug("MEM not available in strncpy read @ {src:x}")
    elif emulator.read_memory(dst, 1) is None:
        logger.debug("MEM not available in strncpy write @ {dst:x}")
    else:
        # at least a byte is available at both src and dst
        ld = _emu_strlen_n(emulator, dst, MAX_STRLEN)
        ls = _emu_strlen_n(emulator, src, MAX_STRLEN)
        lsn = min(ls, n)
        b_opt = emulator.read_memory(src, lsn)
        if b_opt is not None:
            src_bytes = b_opt + b"\0"
            emulator.write_memory(dst + ld, src_bytes)
        else:
            assert b_opt is not None


######################################################
#                 End private stuff                  #
######################################################


class PosixModel(Model):
    # Base class for POSIX models.
    #
    # Most POSIX ABIS use a register-based calling convention.
    # Rather than tailor each model for each ABI, this base class
    # lets us play madlibs with the argument and return registers.
    #
    # TODO: i386 and mips32 also have stack-passed arguments.

    @property
    @abc.abstractmethod
    def argument1(self) -> str:
        return ""

    @property
    @abc.abstractmethod
    def argument2(self) -> str:
        return ""

    @property
    @abc.abstractmethod
    def argument3(self) -> str:
        return ""

    @property
    @abc.abstractmethod
    def argument4(self) -> str:
        return ""

    @property
    @abc.abstractmethod
    def argument5(self) -> str:
        return ""

    @property
    @abc.abstractmethod
    def argument6(self) -> str:
        return ""

    @property
    @abc.abstractmethod
    def return_val(self) -> str:
        return ""


class BasenameModel(PosixModel):
    name = "basename"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *basename(char "path)
        # returns final component (after last '/') of filename
        # if path ends with '/' return a ptr to an empty string
        path = emulator.read_register(self.argument1)
        sl = _emu_strlen_n(emulator, path, MAX_STRLEN)
        bn = None
        while True:
            b_opt = emulator.read_memory(path + sl, 1)
            if b_opt is not None:
                b = b_opt[0]
                if chr(b) == "/":
                    bn = path + sl + 1
                    break
                if sl == 0:
                    bn = path
                    break
                sl = sl - 1
            else:
                assert b_opt is not None
        assert not (bn is None)
        emulator.write_register(self.return_val, bn)


class CallocModel(PosixModel):
    name = "calloc"

    def model(self, emulator: emulators.Emulator) -> None:
        # void *calloc(size_t count, size_t size);
        count = emulator.read_register(self.argument1)
        size = emulator.read_register(self.argument2)
        num_bytes = count * size
        addr = _emu_calloc(emulator, num_bytes)
        emulator.write_register(self.return_val, addr)


class ReturnsNothingModel(PosixModel):
    def model(self, emulator: emulators.Emulator) -> None:
        # so just do nothing
        pass


class Returns0Model(PosixModel):
    def model(self, emulator: emulators.Emulator) -> None:
        # just return 0
        emulator.write_register(self.return_val, 0)


class DaemonModel(Returns0Model):
    name = "daemon"


class FlockModel(Returns0Model):
    name = "flock"


class Getopt_longModel(PosixModel):
    name = "getopt_long"

    def model(self, emulator: emulators.Emulator) -> None:
        # int getopt_long(int argc, char * const *argv, const char *optstring, const struct option *longopts, int *longindex);
        # return -1 if no more args
        emulator.write_register(self.return_val, -1)


class GetpagesizeModel(PosixModel):
    name = "getpagesize"

    def model(self, emulator: emulators.Emulator) -> None:
        # int getpagesize(void);
        emulator.write_register(self.return_val, 0x1000)


class GetppidModel(Returns0Model):
    name = "getppid"


class GetsModel(PosixModel):
    name = "gets"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *gets(char *str);
        s = emulator.read_register(self.argument1)
        value = input()
        emulator.write_memory(s, value.encode("utf-8"))
        emulator.write_register(self.return_val, s)


class MallocModel(CallocModel):
    name = "malloc"


class MemcpyModel(PosixModel):
    name = "memcpy"

    def model(self, emulator: emulators.Emulator) -> None:
        # void *memcpy(void *restrict dst, const void *restrict src, size_t n);
        dst = emulator.read_register(self.argument1)
        src = emulator.read_register(self.argument2)
        n = emulator.read_register(self.argument3)
        _emu_memcpy(emulator, dst, src, n)
        emulator.write_register(self.return_val, dst)


class OpenModel(PosixModel):
    name = "open"

    def model(self, emulator: emulators.Emulator) -> None:
        # int open64(const char *pathname, int oflag,...);
        # just return a fd that's not stdin/stdout/stderr
        emulator.write_register(self.return_val, 3)


class Open64Model(OpenModel):
    name = "open64"


class PutsModel(PosixModel):
    name = "puts"

    def model(self, emulator: emulators.Emulator) -> None:
        # int fputs(const char *restrict s, FILE *restrict stream);
        addr = emulator.read_register_content(self.argument1)
        sl = _emu_strlen(emulator, addr)
        b_opt = emulator.read_memory(addr, sl)
        if b_opt is not None:
            logger.debug(f"puts stream={self.argument2:x} s=[{b_opt!r}]")
        emulator.write_register(self.return_val, 0)


class PthreadCondInitModel(Returns0Model):
    name = "pthread_cond_init"


class PthreadCondSignalModel(Returns0Model):
    name = "pthread_cond_signal_model"


class PthreadCondWaitModel(Returns0Model):
    name = "pthread_cond_wait"


class PthreadCreateModel(Returns0Model):
    name = "pthread_create"


class PthreadMutexInitModel(Returns0Model):
    name = "pthread_mutex_init"


class PthreadMutexLockModel(Returns0Model):
    name = "ptherad_mutex_lock"


class PthreadMutexUnlockModel(Returns0Model):
    name = "pthread_mutex_unlock"


class PtraceModel(Returns0Model):
    name = "ptrace"


class RandModel(PosixModel):
    name = "rand"

    def model(self, emulator: emulators.Emulator) -> None:
        # int rand(void);
        emulator.write_register(self.return_val, random.randint(0, 0x7FFFFFFF))


class RandomModel(PosixModel):
    name = "random"

    def model(self, emulator: emulators.Emulator) -> None:
        # long random(void);
        emulator.write_register(self.return_val, random.randint(0, 0xFFFFFFFF))


class SleepModel(Returns0Model):
    name = "sleep"


class SrandModel(ReturnsNothingModel):
    name = "srand"


class SrandomModel(ReturnsNothingModel):
    name = "srandom"


class StrcatModel(PosixModel):
    name = "strcat"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *strcat(char *restrict s1, const char *restrict s2);
        dst = emulator.read_register(self.argument1)
        src = emulator.read_register(self.argument2)
        _emu_strncat(emulator, dst, src, MAX_STRLEN)


class StrncatModel(PosixModel):
    name = "strncat"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *strncat(char *restrict s1, const char *restrict s2, size_t n);
        dst = emulator.read_register(self.argument1)
        src = emulator.read_register(self.argument2)
        msl = emulator.read_register(self.argument3)
        _emu_strncat(emulator, dst, src, msl)


class StrcpyModel(PosixModel):
    name = "strcpy"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *strcpy(char * dst, const char * src);
        dst = emulator.read_register(self.argument1)
        src = emulator.read_register(self.argument2)
        _emu_strncpy(emulator, dst, src, MAX_STRLEN, is_strncpy=False)


class StrncpyModel(PosixModel):
    name = "strncpy"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *strncpy(char * dst, const char * src, size_t len);
        dst = emulator.read_register(self.argument1)
        src = emulator.read_register(self.argument2)
        sl = emulator.read_register(self.argument3)
        _emu_strncpy(emulator, dst, src, sl, is_strncpy=True)


class StrdupModel(PosixModel):
    name = "strdup"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *strdup(const char *s1);
        src = emulator.read_register(self.argument1)
        sl = _emu_strlen_n(emulator, src, MAX_STRLEN)
        dst = _emu_calloc(emulator, sl)
        _emu_memcpy(emulator, dst, src, sl)
        emulator.write_register(self.return_val, dst)


class StrlenModel(PosixModel):
    name = "strlen"

    def model(self, emulator: emulators.Emulator) -> None:
        # size_t strlen(const char *s)
        ptr = emulator.read_register(self.argument1)
        emulator.write_register(
            self.return_val, _emu_strlen_n(emulator, ptr, MAX_STRLEN)
        )


class StrnlenModel(PosixModel):
    name = "strnlen"

    def model(self, emulator: emulators.Emulator) -> None:
        # size_t strnlen(const char *s, size_t maxlen);
        ptr = emulator.read_register(self.argument1)
        n = emulator.read_register(self.argument2)
        emulator.write_register(self.return_val, _emu_strlen_n(emulator, ptr, n))


class SysconfModel(PosixModel):
    name = "sysconf"

    def model(self, emulator: emulators.Emulator) -> None:
        # long sysconf(int name);
        arg1 = emulator.read_register(self.argument1)
        if arg1 == 0x54:
            # this is the one case we know about so far
            # it's asking for the number of cores
            emulator.write_register(self.return_val, 1)


class TimeModel(PosixModel):
    name = "time"

    def model(self, emulator: emulators.Emulator) -> None:
        # time_t time(time_t *tloc);
        # just return something
        emulator.write_register(self.return_val, 0x1234)


class UnlinkModel(Returns0Model):
    name = "unlink"


class WriteModel(PosixModel):
    name = "write"

    def model(self, emulator: emulators.Emulator) -> None:
        # ssize_t write(int fildes, const void *buf, size_t nbyte);
        addr = emulator.read_register_content(self.argument2)
        size = emulator.read_register_content(self.argument3)
        b_opt = emulator.read_memory(addr, size)
        if b_opt is not None:
            logger.debug(f"write fd={self.argument1} buf=[{b_opt!r}]")
        emulator.write_register(self.return_val, 0)
