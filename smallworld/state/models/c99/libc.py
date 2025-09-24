import inspect
import typing

from ....platforms import ABI, Platform
from ...memory.heap import Heap
from ..library import ElfModelLibrary
from ..model import Model
from . import signal, stdio, stdlib, string, time


class C99Libc(ElfModelLibrary):
    alt_names = {
        "__cxa_atexit": "atexit",
    }

    def __init__(
        self,
        address: int,
        platform: Platform,
        abi: ABI,
        allow_imprecise: typing.Set[str] = set(),
        heap: typing.Optional[Heap] = None,
    ):
        super().__init__(address, platform, abi, allow_imprecise=allow_imprecise)
        if heap is not None:
            malloc_model = self.models["malloc"]
            calloc_model = self.models["calloc"]
            realloc_model = self.models["realloc"]
            free_model = self.models["free"]

            assert hasattr(malloc_model, "heap")
            assert hasattr(calloc_model, "heap")
            assert hasattr(realloc_model, "heap")
            assert hasattr(free_model, "heap")

            malloc_model.heap = heap
            calloc_model.heap = heap
            realloc_model.heap = heap
            free_model.heap = heap

    @property
    def function_names(self) -> typing.List[str]:
        out: typing.List[str] = list()
        for module in (signal, stdio, stdlib, string, time):
            for clsname, cls in inspect.getmembers(
                module,
                lambda x: inspect.isclass(x)
                and issubclass(x, Model)
                and isinstance(x.name, str),
            ):
                out.append(cls.name)
        return out


__all__ = ["C99Libc"]
