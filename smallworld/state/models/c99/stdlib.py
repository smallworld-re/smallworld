import logging
import random
import typing

import claripy

from smallworld.state.models.funcptr import FunctionPointer

from .... import emulators, exceptions
from ...memory.heap import Heap
from ..cstd import ArgumentType, CStdModel
from .utils import _emu_strlen

logger = logging.getLogger("__name__")


class Abort(CStdModel):
    name = "abort"

    # void abort(void);
    argument_types = []
    return_type = ArgumentType.VOID

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise exceptions.EmulationStop("Called abort()")


class Abs(CStdModel):
    name = "abs"

    # int abs(int val);
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    @property
    def sign_mask(self):
        return self._int_sign_mask

    @property
    def inv_mask(self):
        return self._int_inv_mask

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        val = self.get_arg1(emulator)

        assert isinstance(val, int)

        if val & self.sign_mask:
            val = ((val ^ self.inv_mask) + 1) & self.inv_mask

        self.set_return_value(emulator, val)


class LAbs(Abs):
    name = "labs"

    # long labs(long x);
    argument_types = [ArgumentType.LONG]
    return_type = ArgumentType.LONG

    @property
    def sign_mask(self):
        return self._long_sign_mask

    @property
    def inv_mask(self):
        return self._long_inv_mask


class LLAbs(Abs):
    name = "llabs"

    # long long llabs(long long x);
    argument_types = [ArgumentType.LONGLONG]
    return_type = ArgumentType.LONGLONG

    @property
    def sign_mask(self):
        return self._long_long_sign_mask

    @property
    def inv_mask(self):
        return self._long_long_inv_mask


class Atexit(CStdModel):
    name = "atexit"

    # NOTE: In glibc binaries, relocate atexit against __cxa_atexit
    # atexit is a statically-linked helper that calls __cxa_atexit

    # void atexit(void);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # This will not actually result in an exit handler getting registered.
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        self.set_return_value(emulator, 0)


class Atof(CStdModel):
    name = "atof"

    # float atof(const char *str);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.FLOAT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # TODO: Support other locales for atof
        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        n = _emu_strlen(emulator, ptr)

        data = emulator.read_memory(ptr, n)
        text = data.decode("utf-8")

        # This is a bit tricky.  Python is much less accepting than C.
        text = text.strip()
        found_dot = False
        for i in range(0, len(text)):
            if text[i].isnumeric():
                continue
            elif text[i] == ".":
                if found_dot:
                    text = text[0:i]
                    break
                else:
                    found_dot = True
            else:
                text = text[0:i]
                break
        if len(text) == 0:
            text = "0"

        self.set_return_value(emulator, float(text))


class Atoi(CStdModel):
    name = "atoi"

    # int atoi(const char *str);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    size_mask = 0xFFFFFFFF

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # TODO: Support other locales for atoi
        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        n = _emu_strlen(emulator, ptr)

        data = emulator.read_memory(ptr, n)
        text = data.decode("utf-8").strip()
        print(f"Converting {text} ({len(text)})")

        for i in range(0, len(text)):
            if not text[i].isnumeric() and text[i] != "-":
                text = text[0:i]
                break

        if len(text) == 0:
            # No valid number
            self.set_return_value(emulator, 0)
            return

        # TODO: Not entirely sure if this is how truncation will work.
        newval = int(text) & self.size_mask
        self.set_return_value(emulator, newval)


class Atol(Atoi):
    name = "atol"

    # long atoll(const char *str);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.LONG

    size_mask = 0xFFFFFFFFFFFFFFFF


class Atoll(Atoi):
    name = "atoll"

    # long long atoll(const char *str);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.LONGLONG

    size_mask = 0xFFFFFFFFFFFFFFFF


class Bsearch(CStdModel):
    name = "bsearch"

    # void *bsearch(const void *key, const void *base,
    #               size_t nitems, size_t size,
    #               int (*compar)(const void *, const void *));
    argument_types = [
        ArgumentType.POINTER,
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.SIZE_T,
        ArgumentType.POINTER,
    ]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # Not easily possible; need to call a comparator function.
        raise NotImplementedError(
            "bsearch uses a function pointer; not sure how to model"
        )


class Calloc(CStdModel):
    name = "calloc"

    # void *calloc(size_t amount, size_t size);
    argument_types = [ArgumentType.SIZE_T, ArgumentType.SIZE_T]
    return_type = ArgumentType.POINTER

    def __init__(self, address: int):
        super().__init__(address)
        # Use the same heap model the harness used.
        # NOTE: This will get cloned on a deep copy.
        self.heap: typing.Optional[Heap] = None

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        if self.heap is None:
            raise exceptions.ConfigurationError(
                "calloc needs a heap; please assign self.heap"
            )

        amt = self.get_arg1(emulator)
        size = self.get_arg2(emulator)

        assert isinstance(amt, int)
        assert isinstance(size, int)

        data = b"\0" * amt * size

        res = self.heap.allocate_bytes(data, None)
        # This is calloc; zero out the memory
        emulator.write_memory(res, data)

        self.set_return_value(emulator, res)


class Div(CStdModel):
    name = "div"

    # div_t result(int dividend, int divisor);
    argument_types = [ArgumentType.INT, ArgumentType.INT]
    # FIXME: Figure out how different platforms return structs by value

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # div_t result(int dividend, int divisor);
        raise NotImplementedError()


class LDiv(Div):
    name = "ldiv"

    # ldiv_t result(long dividend, long divisor);
    argument_types = [ArgumentType.LONG, ArgumentType.LONG]
    # FIXME: Figure out how different platforms return structs by value


class LLDiv(Div):
    name = "lldiv"

    # lldiv_t result(long long dividend, long long divisor);
    argument_types = [ArgumentType.LONGLONG, ArgumentType.LONGLONG]
    # FIXME: Figure out how different platforms return structs by value


class Exit(CStdModel):
    name = "exit"

    # void exit(int code);
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.VOID

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise exceptions.EmulationStop("Called exit()")


class Free(CStdModel):
    name = "free"

    # void free(void *ptr);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.VOID

    def __init__(self, address: int):
        super().__init__(address)
        # Use the same heap model the harness used.
        # NOTE: This will get cloned on a deep copy.
        self.heap: typing.Optional[Heap] = None

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        if self.heap is None:
            raise exceptions.ConfigurationError(
                "malloc needs a heap; please assign self.heap"
            )

        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        self.heap.free(ptr)


class Getenv(CStdModel):
    name = "getenv"

    # char *getenv(char *name);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    # We don't have a model of envp,
    # so this will always return NULL
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        size = _emu_strlen(emulator, ptr)
        data = emulator.read_memory(ptr, size)
        name = data.decode("utf-8")

        logger.info(f"getenv({name});")
        self.set_return_value(emulator, 0)


class Malloc(CStdModel):
    name = "malloc"

    # void *malloc(size_t size);
    argument_types = [ArgumentType.SIZE_T]
    return_type = ArgumentType.POINTER

    def __init__(self, address: int):
        super().__init__(address)
        # Use the same heap model the harness used.
        # NOTE: This will get cloned on a deep copy.
        self.heap: typing.Optional[Heap] = None

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        if self.heap is None:
            raise exceptions.ConfigurationError(
                "malloc needs a heap; please assign self.heap"
            )

        size = self.get_arg1(emulator)

        assert isinstance(size, int)

        res = self.heap.allocate_bytes(b"\0" * size, None)

        self.set_return_value(emulator, res)


class Mblen(CStdModel):
    name = "mblen"

    # int mblen(char *str, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # Depends the locale.
        raise NotImplementedError()


class Mbstowcs(CStdModel):
    name = "mbstowcs"

    # size_t mbstowcs(schar_t *pwcs, char *str, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.SIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # Depends the locale.
        raise NotImplementedError()


class Mbtowc(CStdModel):
    name = "mbtowc"

    # size_t mbtowc(wchar_t *pwcs, char *str, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # Depends the locale.
        raise NotImplementedError()


class QSort(CStdModel):
    name = "qsort"

    # void qsort(void *arr, size_t amount, size_t size, int (*compare)(const void *, const void *));
    argument_types = [
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.SIZE_T,
        ArgumentType.POINTER,
    ]
    return_type = ArgumentType.VOID

    return_addr = 0

    def model(self, emulator: emulators.Emulator) -> None:
        """This implementation uses Insertion sort as a state machine.
        The model points the emulator at the comparison function and sets the
        return address back to the model until the array has been fully sorted.
        """
        super().model(emulator)

        if not self.skip_return:
            # initialize state machine
            self.return_addr = emulator.read_register("lr")
            emulator.write_register("lr", self._address)

            # collect args
            self.base = typing.cast(int, self.get_arg1(emulator))
            self.nmemb = typing.cast(int, self.get_arg2(emulator))
            self.size = typing.cast(int, self.get_arg3(emulator))
            self.compar = typing.cast(int, self.get_arg4(emulator))
            assert isinstance(self.base, int)
            assert isinstance(self.nmemb, int)
            assert isinstance(self.size, int)
            assert isinstance(self.compar, int)

            # comparison function pointer
            self.compare_func_ptr = FunctionPointer(
                self.compar,
                [ArgumentType.POINTER, ArgumentType.POINTER],
                ArgumentType.INT,
                self.platform,
            )

            # initialize sorting locals and comparison stack frame
            self.i = 1
            self.j = self.i
            self.compare_func_ptr.call(
                emulator,
                [
                    self.base + (self.j * self.size),
                    self.base + (self.j - 1) * self.size,
                ],
            )

            # don't return out of model
            self.skip_return = True

        if self.skip_return:
            # read emulator state
            elem_addrs = [self.base + i * self.size for i in range(0, self.nmemb)]
            current_array = [
                emulator.read_memory(addr, self.size) for addr in elem_addrs
            ]
            ret = self.compare_func_ptr.get_return_value(emulator)

            # swap elements
            if ret < 0:
                tmp = current_array[self.j]
                current_array[self.j] = current_array[self.j - 1]
                current_array[self.j - 1] = tmp
                emulator.write_memory(self.base, b"".join(current_array))

            # iterate
            self.j -= 1
            if self.j <= 0:
                self.i += 1
                self.j = self.i
            self.compare_func_ptr.call(
                emulator,
                [
                    self.base + (self.j * self.size),
                    self.base + (self.j - 1) * self.size,
                ],
            )

            # break if we're sorted
            if self.i > self.nmemb:
                emulator.write_register("lr", self.return_addr)
                self.skip_return = False
            else:
                # return to this model
                emulator.write_register("lr", self._address)


class Rand(CStdModel):
    name = "rand"

    # int rand(void);
    argument_types = []
    return_type = ArgumentType.INT

    rand = random.Random()

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # TODO: Rand is easy to do simply, harder to do right.
        # If someone is relying on srand/rand to produce a specific sequence,
        # this won't behave correctly.
        val = self.rand.randint(0, 2147483647)
        self.set_return_value(emulator, val)


class Realloc(CStdModel):
    name = "realloc"

    # void *realloc(void *ptr, size_t size);
    argument_types = [ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.POINTER

    def __init__(self, address: int):
        super().__init__(address)
        # Use the same heap model the harness used.
        # NOTE: This will get cloned on a deep copy.
        self.heap: typing.Optional[Heap] = None

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        if self.heap is None:
            raise exceptions.ConfigurationError(
                "realloc needs a heap; please assign self.heap"
            )

        ptr = self.get_arg1(emulator)
        size = self.get_arg2(emulator)

        assert isinstance(ptr, int)
        assert isinstance(size, int)

        logger.warning(f"REALLOC {hex(ptr)}, {size}")

        if ptr == 0:
            res = self.heap.allocate_bytes(b"\0" * size, None)
        elif ptr - self.heap.address not in self.heap:
            raise exceptions.EmulationError(
                f"Attempted to realloc {hex(ptr)}, which was not malloc'd on this heap"
            )
        else:
            oldsize = self.heap[ptr - self.heap.address].get_size()
            data: typing.Union[bytes, claripy.ast.bv.BV]
            try:
                data = emulator.read_memory(ptr, oldsize)
            except exceptions.SymbolicValueError:
                data = emulator.read_memory_symbolic(ptr, oldsize)

            self.heap.free(ptr)

            res = self.heap.allocate_bytes(b"\0" * size, None)
            emulator.write_memory(res, data)

        self.set_return_value(emulator, res)


class Srand(CStdModel):
    name = "srand"

    # void srand(int seed);
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.VOID

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        seed = self.get_arg1(emulator)
        Rand.rand.seed(a=seed)


class System(CStdModel):
    name = "system"

    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        size = _emu_strlen(emulator, ptr)
        data = emulator.read_memory(ptr, size)
        cmd = data.decode("utf-8")

        logger.info(f"system({cmd});")
        self.set_return_value(emulator, 0)


class Wcstombs(CStdModel):
    name = "wctombs"

    # size_t wctombs(char *str, wchar_t *pwcs, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.SIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # Depends the locale.
        raise NotImplementedError()


class Wctomb(CStdModel):
    name = "wctomb"

    # int wctomb(char *str, wchar_t wchar);
    argument_types = [ArgumentType.POINTER, ArgumentType.UINT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # Depends the locale.
        raise NotImplementedError()


__all__ = [
    "Abs",
    "LAbs",
    "LLAbs",
    "Abort",
    "Atexit",
    "Atof",
    "Atoi",
    "Atol",
    "Atoll",
    "Calloc",
    "Div",
    "LDiv",
    "LLDiv",
    "Exit",
    "Free",
    "Getenv",
    "Malloc",
    "Mblen",
    "Mbstowcs",
    "Mbtowc",
    "QSort",
    "Rand",
    "Realloc",
    "Srand",
    "System",
    "Wcstombs",
    "Wctomb",
]
