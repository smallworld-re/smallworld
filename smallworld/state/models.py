import abc
import inspect
import logging
import random
import typing

from .. import emulators, initializers
from . import state

logger = logging.getLogger(__name__)

MAX_STRLEN = 0x10000


######################################################
# This stuff is private. Dont' add it to __all__     #
######################################################

# next, last available byte in heap
heap_next = None
heap_last = None


def _get_page(emulator: emulators.Emulator, addr: int) -> int:
    return addr // emulator.PAGE_SIZE


# obtain addr of emulator heap memory of this size
# NB: this will map new pages into emulator as needed
def _emu_alloc(emulator: emulators.Emulator, size: int) -> int:
    global heap_next, heap_last
    if heap_next is None:
        # first dynamic alloc
        num_pages = (size // emulator.PAGE_SIZE) + 1
        page_start = emulator.get_pages(num_pages)
        heap_last = page_start + num_pages * emulator.PAGE_SIZE - 1
        alloc_addr = page_start
        heap_next = page_start + size
    else:
        first_addr = heap_next
        last_addr = heap_next + size - 1
        if last_addr <= heap_last:
            # allocation fits in currently mapped and available heap
            alloc_addr = heap_next
            heap_next += size
        else:
            # alloc wont fit
            first_page = _get_page(first_addr)
            last_page = _get_page(last_addr)
            num_new_pages = (last_page - first_page) / emulator.PAGE_SIZE
            new_pages_start = emulator.get_pages(num_new_pages)
            # assume (but verify) that next page will be just what we already have
            current_last_page_start = _get_page(heap_last)
            assert current_last_page_start + emulator.PAGE_SIZE == new_pages_start
            alloc_addr = heap_next
            heap_next += size
    return alloc_addr


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


class Model(state.Value):
    """A runtime function model implemented in Python.

    If execution reaches the given address, call the given function instead of
    any code at that address and return.

    Arguments:
        address: The address to hook.
        function: The model function.
    """

    def __init__(
        self, address: int, function: typing.Callable[[emulators.Emulator], None]
    ):
        self.address = address
        self.function = function

    @property
    def value(self):
        raise NotImplementedError()

    @value.setter
    def value(self, value) -> None:
        raise NotImplementedError()

    def initialize(
        self, initializer: initializers.Initializer, override: bool = False
    ) -> None:
        logger.debug(f"skipping initialization for {self} (hook)")

    def load(self, emulator: emulators.Emulator, override: bool = True) -> None:
        logger.debug(f"{self} loading not supported - load skipped")

    def apply(self, emulator: emulators.Emulator) -> None:
        logger.debug(f"hooking {self} {self.address:x}")
        emulator.hook(self.address, self.function, finish=True)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(0x{self.address:x}:{self.function.__name__})"


class ImplementedModel(Model):
    @abc.abstractmethod
    def model(self, emulator: emulators.Emulator) -> None:
        pass

    @property
    @abc.abstractmethod
    def name(self):
        pass

    @property
    @abc.abstractmethod
    def argument1(self):
        pass

    @property
    @abc.abstractmethod
    def argument2(self):
        pass

    @property
    @abc.abstractmethod
    def argument3(self):
        pass

    @property
    @abc.abstractmethod
    def return_val(self):
        pass

    def __init__(self, address: int):
        def model(emulator: emulators.Emulator) -> None:
            self.model(emulator)

        super().__init__(address, model)


class ReturnsNothingImplementedModel(ImplementedModel):
    def model(self, emulator: emulators.Emulator) -> None:
        # so just do nothing
        pass


class Returns0ImplementedModel(ImplementedModel):
    def model(self, emulator: emulators.Emulator) -> None:
        # just return 0
        emulator.write_register(self.return_val, 0)


class BasenameModel(ImplementedModel):
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


class CallocModel(ImplementedModel):
    name = "calloc"

    def model(self, emulator: emulators.Emulator) -> None:
        # void *calloc(size_t count, size_t size);
        count = emulator.read_register(self.argument1)
        size = emulator.read_register(self.argument2)
        num_bytes = count * size
        addr = _emu_calloc(emulator, num_bytes)
        emulator.write_register(self.return_val, addr)


class DaemonModel(Returns0ImplementedModel):
    name = "daemon"


class FlockModel(Returns0ImplementedModel):
    name = "flock"


class Getopt_longModel(ImplementedModel):
    name = "getopt_long"

    def model(self, emulator: emulators.Emulator) -> None:
        # int getopt_long(int argc, char * const *argv, const char *optstring, const struct option *longopts, int *longindex);
        # return -1 if no more args
        emulator.write_register(self.return_val, -1)


class GetpagesizeModel(ImplementedModel):
    name = "getpagesize"

    def model(self, emulator: emulators.Emulator) -> None:
        # int getpagesize(void);
        emulator.write_register(self.return_val, 0x1000)


class GetppidModel(Returns0ImplementedModel):
    name = "getppid"


class GetsModel(ImplementedModel):
    name = "gets"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *gets(char *str);
        s = emulator.read_register(self.argument1)
        value = input()
        emulator.write_memory(s, value.encode("utf-8"))
        emulator.write_register(self.return_val, s)


class MallocModel(CallocModel):
    name = "malloc"


class MemcpyModel(ImplementedModel):
    name = "memcpy"

    def model(self, emulator: emulators.Emulator) -> None:
        # void *memcpy(void *restrict dst, const void *restrict src, size_t n);
        dst = emulator.read_register(self.argument1)
        src = emulator.read_register(self.argument2)
        n = emulator.read_register(self.argument3)
        _emu_memcpy(emulator, dst, src, n)
        emulator.write_register(self.return_val, dst)


class OpenModel(ImplementedModel):
    name = "open"

    def model(self, emulator: emulators.Emulator) -> None:
        # int open64(const char *pathname, int oflag,...);
        # just return a fd that's not stdin/stdout/stderr
        emulator.write_register(self.return_val, 3)


class Open64Model(OpenModel):
    name = "open64"


class PutsModel(ImplementedModel):
    name = "puts"

    def model(self, emulator: emulators.Emulator) -> None:
        # int fputs(const char *restrict s, FILE *restrict stream);
        sl = _emu_strlen(emulator, self.argument1)
        b_opt = emulator.read_memory(self.argument1, sl)
        if b_opt is not None:
            logger.debug(f"puts stream={self.argument2:x} s=[{b_opt!r}]")
        emulator.write_register(self.return_val, 0)


class PthreadCondInitModel(Returns0ImplementedModel):
    name = "pthread_cond_init"


class PthreadCondSignalModel(Returns0ImplementedModel):
    name = "pthread_cond_signal_model"


class PthreadCondWaitModel(Returns0ImplementedModel):
    name = "pthread_cond_wait"


class PthreadCreateModel(Returns0ImplementedModel):
    name = "pthread_create"


class PthreadMutexInitModel(Returns0ImplementedModel):
    name = "pthread_mutex_init"


class PthreadMutexLockModel(Returns0ImplementedModel):
    name = "ptherad_mutex_lock"


class PthreadMutexUnlockModel(Returns0ImplementedModel):
    name = "pthread_mutex_unlock"


class PtraceModel(Returns0ImplementedModel):
    name = "ptrace"


class RandModel(ImplementedModel):
    name = "rand"

    def model(self, emulator: emulators.Emulator) -> None:
        # int rand(void);
        emulator.write_register(self.return_val, random.randint(0, 0x7FFFFFFF))


class RandomModel(ImplementedModel):
    name = "random"

    def model(self, emulator: emulators.Emulator) -> None:
        # long random(void);
        emulator.write_register(self.return_val, random.randint(0, 0xFFFFFFFF))


class SleepModel(Returns0ImplementedModel):
    name = "sleep"


class SrandModel(ReturnsNothingImplementedModel):
    name = "srand"


class SrandomModel(ReturnsNothingImplementedModel):
    name = "srandom"


class StrcatModel(ImplementedModel):
    name = "strcat"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *strcat(char *restrict s1, const char *restrict s2);
        dst = emulator.read_register(self.argument1)
        src = emulator.read_register(self.argument2)
        _emu_strncat(emulator, dst, src, MAX_STRLEN)


class StrncatModel(ImplementedModel):
    name = "strncat"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *strncat(char *restrict s1, const char *restrict s2, size_t n);
        dst = emulator.read_register(self.argument1)
        src = emulator.read_register(self.argument2)
        msl = emulator.read_register(self.argument3)
        _emu_strncat(emulator, dst, src, msl)


class StrcpyModel(ImplementedModel):
    name = "strcpy"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *strcpy(char * dst, const char * src);
        dst = emulator.read_register(self.argument1)
        src = emulator.read_register(self.argument2)
        _emu_strncpy(emulator, dst, src, MAX_STRLEN, is_strncpy=False)


class StrncpyModel(ImplementedModel):
    name = "strncpy"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *strncpy(char * dst, const char * src, size_t len);
        dst = emulator.read_register(self.argument1)
        src = emulator.read_register(self.argument2)
        sl = emulator.read_register(self.argument3)
        _emu_strncpy(emulator, dst, src, sl, is_strncpy=True)


class StrdupModel(ImplementedModel):
    name = "strdup"

    def model(self, emulator: emulators.Emulator) -> None:
        # char *strdup(const char *s1);
        src = emulator.read_register(self.argument1)
        sl = _emu_strlen_n(emulator, src, MAX_STRLEN)
        dst = _emu_calloc(emulator, sl)
        _emu_memcpy(emulator, dst, src, sl)
        emulator.write_register(self.return_val, dst)


class StrlenModel(ImplementedModel):
    name = "strlen"

    def model(self, emulator: emulators.Emulator) -> None:
        # size_t strlen(const char *s)
        ptr = emulator.read_register(self.argument1)
        emulator.write_register(
            self.return_val, _emu_strlen_n(emulator, ptr, MAX_STRLEN)
        )


class StrnlenModel(ImplementedModel):
    name = "strnlen"

    def model(self, emulator: emulators.Emulator) -> None:
        # size_t strnlen(const char *s, size_t maxlen);
        ptr = emulator.read_register(self.argument1)
        n = emulator.read_register(self.argument2)
        emulator.write_register(self.return_val, _emu_strlen_n(emulator, ptr, n))


class SysconfModel(ImplementedModel):
    name = "sysconf"

    def model(self, emulator: emulators.Emulator) -> None:
        # long sysconf(int name);
        arg1 = emulator.read_register(self.argument1)
        if arg1 == 0x54:
            # this is the one case we know about so far
            # it's asking for the number of cores
            emulator.write_register(self.return_val, 1)


class TimeModel(ImplementedModel):
    name = "time"

    def model(self, emulator: emulators.Emulator) -> None:
        # time_t time(time_t *tloc);
        # just return something
        emulator.write_register(self.return_val, 0x1234)


class UnlinkModel(Returns0ImplementedModel):
    name = "unlink"


class WriteModel(ImplementedModel):
    name = "write"

    def model(self, emulator: emulators.Emulator) -> None:
        # ssize_t write(int fildes, const void *buf, size_t nbyte);
        b_opt = emulator.read_memory(self.argument2, self.argument3)
        if b_opt is not None:
            logger.debug(f"write fd={self.argument1} buf=[{b_opt!r}]")
        emulator.write_register(self.return_val, 0)


class AMD64SystemVImplementedModel:
    argument1 = "rdi"
    argument2 = "rsi"
    argument3 = "rdx"
    argument4 = "rcx"
    argument5 = "r8"
    argument6 = "r9"
    return_val = "rax"


class AMD64SystemVBasenameModel(AMD64SystemVImplementedModel, BasenameModel):
    pass


class AMD64SystemVCallocModel(AMD64SystemVImplementedModel, CallocModel):
    pass


class AMD64SystemVDaemonModel(AMD64SystemVImplementedModel, DaemonModel):
    pass


class AMD64SystemVFlockModel(AMD64SystemVImplementedModel, FlockModel):
    pass


class AMD64SystemVGetopt_longModel(AMD64SystemVImplementedModel, Getopt_longModel):
    pass


class AMD64SystemVGetpagesizeModel(AMD64SystemVImplementedModel, GetpagesizeModel):
    pass


class AMD64SystemVGetppidModel(AMD64SystemVImplementedModel, GetppidModel):
    pass


class AMD64SystemVGetsModel(AMD64SystemVImplementedModel, GetsModel):
    pass


class AMD64SystemVMallocModel(AMD64SystemVImplementedModel, MallocModel):
    pass


class AMD64SystemVOpenModel(AMD64SystemVImplementedModel, OpenModel):
    pass


class AMD64SystemVOpen64Model(AMD64SystemVImplementedModel, Open64Model):
    pass


class AMD64SystemVPutsModel(AMD64SystemVImplementedModel, PutsModel):
    pass


class AMD64SystemVPthreadCondInitModel(
    AMD64SystemVImplementedModel, PthreadCondInitModel
):
    pass


class AMD64SystemVPthreadCondSignalModel(
    AMD64SystemVImplementedModel, PthreadCondSignalModel
):
    pass


class AMD64SystemVPthreadCondWaitModel(
    AMD64SystemVImplementedModel, PthreadCondWaitModel
):
    pass


class AMD64SystemVPthreadCreateModel(AMD64SystemVImplementedModel, PthreadCreateModel):
    pass


class AMD64SystemVPthreadMutexInitModel(
    AMD64SystemVImplementedModel, PthreadMutexInitModel
):
    pass


class AMD64SystemVPthreadMutexLockModel(
    AMD64SystemVImplementedModel, PthreadMutexLockModel
):
    pass


class AMD64SystemVPthreadMutexUnlockModel(
    AMD64SystemVImplementedModel, PthreadMutexUnlockModel
):
    pass


class AMD64SystemVPtraceModel(AMD64SystemVImplementedModel, PtraceModel):
    pass


class AMD64SystemVRandModel(AMD64SystemVImplementedModel, RandModel):
    pass


class AMD64SystemVRandomModel(AMD64SystemVImplementedModel, RandomModel):
    pass


class AMD64SystemVSleepModel(AMD64SystemVImplementedModel, SleepModel):
    pass


class AMD64SystemVSrandModel(AMD64SystemVImplementedModel, SrandModel):
    pass


class AMD64SystemVSrandomModel(AMD64SystemVImplementedModel, SrandomModel):
    pass


class AMD64SystemVStrcatModel(AMD64SystemVImplementedModel, StrcatModel):
    pass


class AMD64SystemVStrncatModel(AMD64SystemVImplementedModel, StrncatModel):
    pass


class AMD64SystemVStrcpyModel(AMD64SystemVImplementedModel, StrcpyModel):
    pass


class AMD64SystemVStrncpyModel(AMD64SystemVImplementedModel, StrncpyModel):
    pass


class AMD64SystemVStrdupModel(AMD64SystemVImplementedModel, StrdupModel):
    pass


class AMD64SystemVStrlenModel(AMD64SystemVImplementedModel, StrlenModel):
    pass


class AMD64SystemVStrnlenModel(AMD64SystemVImplementedModel, StrnlenModel):
    pass


class AMD64SystemVSysconfModel(AMD64SystemVImplementedModel, SysconfModel):
    pass


class AMD64SystemVTimeModel(AMD64SystemVImplementedModel, TimeModel):
    pass


class AMD64SystemVUnlinkModel(AMD64SystemVImplementedModel, UnlinkModel):
    pass


class AMD64SystemVWriteModel(AMD64SystemVImplementedModel, WriteModel):
    pass


class AMD64MicrosoftGetsModel(GetsModel):
    pass


class AMD64SystemVNullModel(AMD64SystemVImplementedModel, Returns0ImplementedModel):
    name = "null"


__all__ = [
    #    "Model",
    "AMD64SystemVBasenameModel",
    "AMD64SystemVCallocModel",
    "AMD64SystemVDaemonModel",
    "AMD64SystemVFlockModel",
    "AMD64SystemVGetopt_longModel",
    "AMD64SystemVGetpagesizeModel",
    "AMD64SystemVGetppidModel",
    "AMD64SystemVGetsModel",
    "AMD64SystemVMallocModel",
    "AMD64SystemVOpenModel",
    "AMD64SystemVOpen64Model",
    "AMD64SystemVPthreadCondInitModel",
    "AMD64SystemVPthreadCondSignalModel",
    "AMD64SystemVPthreadCondWaitModel",
    "AMD64SystemVPthreadCreateModel",
    "AMD64SystemVPthreadMutexInitModel",
    "AMD64SystemVPthreadMutexLockModel",
    "AMD64SystemVPthreadMutexUnlockModel",
    "AMD64SystemVPtraceModel",
    "AMD64SystemVPutsModel",
    "AMD64SystemVRandModel",
    "AMD64SystemVRandomModel",
    "AMD64SystemVSleepModel",
    "AMD64SystemVSrandModel",
    "AMD64SystemVSrandomModel",
    "AMD64SystemVStrcatModel",
    "AMD64SystemVStrncatModel",
    "AMD64SystemVStrcpyModel",
    "AMD64SystemVStrncpyModel",
    "AMD64SystemVStrdupModel",
    "AMD64SystemVStrlenModel",
    "AMD64SystemVSysconfModel",
    "AMD64SystemVTimeModel",
    "AMD64SystemVUnlinkModel",
    "AMD64SystemVWriteModel",
    "AMD64MicrosoftGetsModel",
]


def get_models_by_name(
    fn_name: str, desiredHigherClass: typing.Any
) -> typing.List[typing.Any]:
    """Returns list of classes that implement a model for some external function with this name

    Arguments:
        fn_name: The name of the function you want models for

    Returns:
        list of classes that match by name
    """

    # XXX I wanted 2nd arg to be a class like AMD64SystemVImplementedModel
    # and output to be ImplementedModel
    # but could not get this to pass mypi

    models = []
    for name in __all__:
        glb = globals()[name]
        if inspect.isclass(glb):
            model_class = glb
            if hasattr(model_class, "name"):
                if (
                    issubclass(model_class, desiredHigherClass)
                    and model_class.name == fn_name
                ):
                    models.append(model_class)
    return models
