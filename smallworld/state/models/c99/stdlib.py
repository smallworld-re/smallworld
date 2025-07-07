import random
import typing

from .... import emulators, exceptions
from ...memory.heap import Heap
from ..cstd import ArgumentType, CStdModel
from .utils import _emu_strlen


class Abs(CStdModel):
    name = "abs"

    # int abs(int val);
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    sig_mask = 0x80000000
    inv_mask = 0xFFFFFFFF

    def model(self, emulator: emulators.Emulator) -> None:
        val = self.get_arg1(emulator)

        assert isinstance(val, int)

        if val & self.sig_mask:
            val = ((val ^ self.inv_mask) + 1) & self.inv_mask

        self.set_return_value(emulator, val)


class LAbs(Abs):
    name = "labs"

    # long labs(long x);
    argument_types = [ArgumentType.LONG]
    return_type = ArgumentType.LONG

    sig_mask = 0x8000000000000000
    inv_mask = 0xFFFFFFFFFFFFFFFF


class LLAbs(Abs):
    name = "llabs"

    # long long llabs(long long x);
    argument_types = [ArgumentType.LONGLONG]
    return_type = ArgumentType.LONGLONG

    sig_mask = 0x8000000000000000
    inv_mask = 0xFFFFFFFFFFFFFFFF


class Atof(CStdModel):
    name = "atof"

    # float atof(const char *str);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.FLOAT

    def model(self, emulator: emulators.Emulator) -> None:
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
        if self.heap is None:
            raise exceptions.ConfigurationError(
                "malloc needs a heap; please assign self.heap"
            )

        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        self.heap.free(ptr)


class Malloc(CStdModel):
    name = "malloc"

    # void *malloc(size_t size);
    argument_types = [ArgumentType.SIZE_T]
    return_type = ArgumentType.VOID

    def __init__(self, address: int):
        super().__init__(address)
        # Use the same heap model the harness used.
        # NOTE: This will get cloned on a deep copy.
        self.heap: typing.Optional[Heap] = None

    def model(self, emulator: emulators.Emulator) -> None:
        if self.heap is None:
            raise exceptions.ConfigurationError(
                "malloc needs a heap; please assign self.heap"
            )

        size = self.get_arg1(emulator)

        assert isinstance(size, int)

        res = self.heap.allocate_bytes(b"\0" * size, None)

        self.set_return_value(emulator, res)


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

    def model(self, emulator: emulators.Emulator) -> None:
        # Not easily possible; need to call a comparator function.
        raise NotImplementedError(
            "qsort uses a function pointer; not sure how to model"
        )


class Rand(CStdModel):
    name = "rand"

    # int rand(void);
    argument_types = []
    return_type = ArgumentType.INT

    rand = random.Random()

    def model(self, emulator: emulators.Emulator) -> None:
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
        if self.heap is None:
            raise exceptions.ConfigurationError(
                "realloc needs a heap; please assign self.heap"
            )

        ptr = self.get_arg1(emulator)
        size = self.get_arg2(emulator)

        assert isinstance(ptr, int)
        assert isinstance(size, int)

        if ptr == 0:
            res = self.heap.allocate_bytes(b"\0" * size, None)
        elif ptr - self.heap.address not in self.heap:
            raise exceptions.EmulationError(
                f"Attempted to realloc {hex(ptr)}, which was not malloc'd on this heap"
            )
        else:
            oldsize = self.heap[ptr - self.heap.address].get_size()
            data = emulator.read_memory(ptr, oldsize)
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
        seed = self.get_arg1(emulator)
        Rand.rand.seed(a=seed)


__all__ = [
    "Abs",
    "LAbs",
    "LLAbs",
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
    "Malloc",
    "QSort",
    "Rand",
    "Realloc",
    "Srand",
]
