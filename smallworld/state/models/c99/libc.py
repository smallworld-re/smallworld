import inspect
import typing

from ....platforms import ABI, Platform
from ...memory.heap import Heap
from ..filedesc import FileDescriptorManager
from ..library import ElfModelLibrary
from ..model import Model
from . import ctype, signal, stdio, stdlib, string, time


class C99Libc(ElfModelLibrary):
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
            tls_model = self.models["__tls_get_addr"]

            assert hasattr(malloc_model, "heap")
            assert hasattr(calloc_model, "heap")
            assert hasattr(realloc_model, "heap")
            assert hasattr(free_model, "heap")
            assert hasattr(tls_model, "heap")

            malloc_model.heap = heap
            calloc_model.heap = heap
            realloc_model.heap = heap
            free_model.heap = heap
            # __tls_get_addr hands out heap-backed storage for thread-locals.
            tls_model.heap = heap

            fdmgr = FileDescriptorManager.for_platform(platform, abi)
            self.write_int(
                self.variable_addrs["stdin"],
                fdmgr.stdin_filestar,
                self.platdef.address_size,
                self.platform.byteorder,
            )
            self.write_int(
                self.variable_addrs["stdout"],
                fdmgr.stdout_filestar,
                self.platdef.address_size,
                self.platform.byteorder,
            )
            self.write_int(
                self.variable_addrs["stderr"],
                fdmgr.stderr_filestar,
                self.platdef.address_size,
                self.platform.byteorder,
            )

    @property
    def alt_names(self) -> typing.Dict[str, str]:
        return {
            "__cxa_atexit": "atexit",
            "__isoc99_fscanf": "fscanf",
            "__isoc23_fscanf": "fscanf",
            "__isoc99_scanf": "scanf",
            "__isoc23_scanf": "scanf",
            "__isoc99_sscanf": "sscanf",
            "__isoc23_sscanf": "sscanf",
            # _FORTIFY_SOURCE variants take the same leading args as their base
            # function plus a trailing destination-size argument, which the base
            # model simply ignores -- so aliasing is safe for the mem/str copy
            # family. (The printf-family *_chk prepend a flag arg and are NOT
            # safe to alias; they need dedicated models.)
            "__memcpy_chk": "memcpy",
            "__memmove_chk": "memmove",
            "__memset_chk": "memset",
            "__strcpy_chk": "strcpy",
            "__strcat_chk": "strcat",
            "__strncpy_chk": "strncpy",
            "__strncat_chk": "strncat",
        }

    @property
    def function_names(self) -> typing.List[str]:
        out: typing.List[str] = list()
        for module in (ctype, signal, stdio, stdlib, string, time):
            for clsname, cls in inspect.getmembers(
                module,
                lambda x: inspect.isclass(x)
                and issubclass(x, Model)
                and isinstance(x.name, str),
            ):
                out.append(cls.name)
        return out

    @property
    def variables(self) -> typing.List[typing.Tuple[str, int]]:
        return [
            ("stdin", self.platdef.address_size),
            ("stdout", self.platdef.address_size),
            ("stderr", self.platdef.address_size),
        ]


__all__ = ["C99Libc"]
