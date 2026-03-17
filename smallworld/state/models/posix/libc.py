import inspect
import typing

from ..c99.libc import C99Libc
from ..model import Model
from . import libgen, signal, sys, unistd


class POSIXLibc(C99Libc):
    @property
    def function_names(self) -> typing.List[str]:
        out = super().function_names

        for module in (libgen, signal, sys, unistd):
            for clsname, cls in inspect.getmembers(
                module,
                lambda x: inspect.isclass(x)
                and issubclass(x, Model)
                and isinstance(x.name, str),
            ):
                out.append(cls.name)
        return out


__all__ = ["POSIXLibc"]
