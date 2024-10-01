from .. import state
from .posix import GetsModel


class AMD64Win32Model(state.models.Model):
    arch = "x86"
    mode = "64"
    byteorder = "little"
    abi = "win32"

    # NOTE: according to Wikipedia, win32 only allows 4 register-passed arguments.
    argument1 = "rcx"
    argument2 = "rdx"
    argument3 = "r8"
    argument4 = "r9"

    return_val = "rax"


class AMD64MicrosoftGetsModel(AMD64Win32Model, GetsModel):
    pass
