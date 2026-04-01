import inspect
import typing

from ..c99.libc import C99Libc
from ..model import Model
from . import arpa, libgen, signal, sys, unistd


class POSIXLibc(C99Libc):
    @property
    def alt_names(self) -> typing.Dict[str, str]:
        return {
            **super().alt_names,
            "__xpg_basename": "basename",
        }

    @property
    def function_names(self) -> typing.List[str]:
        out = super().function_names

        for module in (arpa, libgen, signal, sys, unistd):
            for clsname, cls in inspect.getmembers(
                module,
                lambda x: inspect.isclass(x)
                and issubclass(x, Model)
                and isinstance(x.name, str),
            ):
                out.append(cls.name)

        return out


__all__ = ["POSIXLibc"]
