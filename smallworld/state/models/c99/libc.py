import inspect
import typing

from ..library import ElfModelLibrary
from ..model import Model
from . import signal, stdio, stdlib, string, time


class C99ElfModelLibrary(ElfModelLibrary):
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
                print(f"{clsname} -> {cls.name}")
                out.append(cls.name)
        return out


__all__ = ["C99ElfModelLibrary"]
