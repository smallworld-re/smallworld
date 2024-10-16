import typing

from .... import platforms
from ..model import Model
from ..posix import GetsModel


class AMD64Win32Model(Model):
    platform = platforms.Platform(
        platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
    )
    abi = platforms.ABI.CDECL

    # NOTE: according to Wikipedia, win32 only allows 4 register-passed arguments.
    argument1 = "rcx"
    argument2 = "rdx"
    argument3 = "r8"
    argument4 = "r9"

    @property
    def argument5(self) -> str:
        raise ValueError("win32 has no argument 5 register")

    @property
    def argument6(self) -> str:
        raise ValueError("win32 has no argument 6 register")

    return_val = "rax"


class AMD64MicrosoftGetsModel(AMD64Win32Model, GetsModel):
    pass


__all__: typing.List[str] = []
