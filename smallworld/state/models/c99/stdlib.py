import random
import struct
import typing

from .... import emulators, exceptions, platforms
from ...memory.heap import Heap
from ..cstd import CStdModel
from .utils import _emu_strlen


class Abs(CStdModel):
    name = "abs"

    sig_mask = 0x80000000
    inv_mask = 0xFFFFFFFF

    def model(self, emulator: emulators.Emulator) -> None:
        # int abs(int val);
        val = self.get_arg1(emulator)

        if val & self.sig_mask:
            val = ((val ^ self.inv_mask) + 1) & self.inv_mask

        self.set_return_value(emulator, val)


class LAbs(Abs):
    name = "labs"
    sig_mask = 0x8000000000000000
    inv_mask = 0xFFFFFFFFFFFFFFFF


class LLAbs(Abs):
    name = "llabs"
    sig_mask = 0x8000000000000000
    inv_mask = 0xFFFFFFFFFFFFFFFF


class Atof(CStdModel):
    name = "atof"

    def model(self, emulator: emulators.Emulator) -> None:
        # float atof(const char *str);
        # TODO: Support other locales for atof
        ptr = self.get_arg1(emulator)
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

        # Now to cram a float into an integer register...
        num = float(text)
        byteorder: typing.Literal["little", "big"]
        if emulator.platform.byteorder == platforms.Byteorder.LITTLE:
            fmt = "<f"
            byteorder = "little"
        elif emulator.platform.byteorder == platforms.Byteorder.BIG:
            fmt = ">f"
            byteorder = "big"
        else:
            raise exceptions.ConfigurationError(
                f"Can't encode for byteorder {emulator.platform}"
            )

        newdata = struct.pack(fmt, num)

        newval = int.from_bytes(newdata, byteorder)

        self.set_return_value(emulator, newval)


class Atoi(CStdModel):
    name = "atoi"
    size_mask = 0xFFFFFFFF

    def model(self, emulator: emulators.Emulator) -> None:
        # int atoi(const char *str);
        # TODO: Support other locales for atof
        ptr = self.get_arg1(emulator)
        n = _emu_strlen(emulator, ptr)

        data = emulator.read_memory(ptr, n)
        text = data.decode("utf-8").strip()

        for i in range(0, len(text)):
            if not text[i].isnumeric():
                text = text[0:i]

        if len(text) == 0:
            # No valid number
            self.set_return_value(emulator, 0)
            return

        # TODO: Not entirely sure if this is how truncation will work.
        newval = int(text) & self.size_mask
        self.set_return_value(emulator, newval)


class Atol(Atoi):
    name = "atol"
    size_mask = 0xFFFFFFFFFFFFFFFF


class Atoll(Atoi):
    name = "atoll"
    size_mask = 0xFFFFFFFFFFFFFFFF


class Calloc(CStdModel):
    name = "calloc"

    def __init__(self, address: int):
        super().__init__(address)
        # Use the same heap model the harness used.
        # NOTE: This will get cloned on a deep copy.
        self.heap: typing.Optional[Heap] = None

    def model(self, emulator: emulators.Emulator) -> None:
        # void *calloc(size_t amount, size_t size);
        if self.heap is None:
            raise exceptions.ConfigurationError(
                "calloc needs a heap; please assign self.heap"
            )

        amt = self.get_arg1(emulator)
        size = self.get_arg2(emulator)

        data = b"\0" * amt * size

        res = self.heap.allocate_bytes(data, None)
        # This is calloc; zero out the memory
        emulator.write_memory(res, data)

        self.set_return_value(emulator, res)


class Div(CStdModel):
    name = "div"
    ret_size = 4

    def model(self, emulator: emulators.Emulator) -> None:
        # div_t result(int dividend, int divisor);
        # FIXME: Figure out how different platforms return structs
        raise NotImplementedError()


class LDiv(Div):
    name = "ldiv"
    ret_size = 8


class LLDiv(Div):
    name = "lldiv"
    ret_size = 8


class Exit(CStdModel):
    name = "exit"

    def model(self, emulator: emulators.Emulator) -> None:
        raise exceptions.EmulationStop("Called exit()")


class Free(CStdModel):
    name = "free"

    def __init__(self, address: int):
        super().__init__(address)
        # Use the same heap model the harness used.
        # NOTE: This will get cloned on a deep copy.
        self.heap: typing.Optional[Heap] = None

    def model(self, emulator: emulators.Emulator) -> None:
        # void free(void *ptr);
        if self.heap is None:
            raise exceptions.ConfigurationError(
                "malloc needs a heap; please assign self.heap"
            )

        ptr = self.get_arg1(emulator)
        self.heap.free(ptr)


class Malloc(CStdModel):
    name = "malloc"

    def __init__(self, address: int):
        super().__init__(address)
        # Use the same heap model the harness used.
        # NOTE: This will get cloned on a deep copy.
        self.heap: typing.Optional[Heap] = None

    def model(self, emulator: emulators.Emulator) -> None:
        # void *malloc(size_t size);
        if self.heap is None:
            raise exceptions.ConfigurationError(
                "malloc needs a heap; please assign self.heap"
            )

        size = self.get_arg1(emulator)

        res = self.heap.allocate_bytes(b"\0" * size, None)

        self.set_return_value(emulator, res)


class QSort(CStdModel):
    name = "qsort"

    def model(self, emulator: emulators.Emulator) -> None:
        # void qsort(void *arr, size_t amount, size_t size, int (*compare)(const void *, const void *));
        # Not easily possible; need to call a comparator function.
        raise NotImplementedError(
            "qsort uses a function pointer; not sure how to model"
        )


class Rand(CStdModel):
    name = "rand"
    rand = random.Random()

    def model(self, emulator: emulators.Emulator) -> None:
        # int rand(void);
        # TODO: Rand is easy to do simply, harder to do right.
        # If someone is relying on srand/rand to produce a specific sequence,
        # this won't behave correctly.
        val = self.rand.randint(0, 2147483647)
        self.set_return_value(emulator, val)


class Realloc(CStdModel):
    name = "realloc"

    def __init__(self, address: int):
        super().__init__(address)
        # Use the same heap model the harness used.
        # NOTE: This will get cloned on a deep copy.
        self.heap: typing.Optional[Heap] = None

    def model(self, emulator: emulators.Emulator) -> None:
        # void *realloc(void *ptr, size_t size);
        if self.heap is None:
            raise exceptions.ConfigurationError(
                "realloc needs a heap; please assign self.heap"
            )

        ptr = self.get_arg1(emulator)
        size = self.get_arg2(emulator)

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
