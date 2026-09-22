import logging

from .... import emulators
from ....platforms import Architecture
from ..c99.utils import _emu_strlen
from ..cstd import ArgumentType
from ..filedesc import FDIOError
from .unistd import FDModel

logger = logging.getLogger(__name__)

# open()'s access mode occupies the low two bits and is identical across every
# Linux ABI. The option bits are not: the asm-generic values below hold on
# every architecture we model except MIPS, which uses its own O_CREAT and
# O_APPEND (its O_TRUNC coincidentally matches). Selecting the right set by
# architecture is what keeps open()/creat() faithful on MIPS.
O_ACCMODE = 0o3
O_RDONLY = 0o0
O_WRONLY = 0o1
O_RDWR = 0o2

#: (O_CREAT, O_TRUNC, O_APPEND) for the asm-generic ABI.
_GENERIC_OFLAGS = (0o100, 0o1000, 0o2000)
#: (O_CREAT, O_TRUNC, O_APPEND) for MIPS.
_MIPS_OFLAGS = (0o400, 0o1000, 0o10)


class Open(FDModel):
    name = "open"

    # int open(const char *pathname, int flags, ... /* mode_t mode */);
    # The variadic mode argument (permissions) is not modeled.
    argument_types = [ArgumentType.POINTER, ArgumentType.INT]
    return_type = ArgumentType.INT

    def _option_flags(self) -> tuple:
        if self.platform.architecture in (Architecture.MIPS32, Architecture.MIPS64):
            return _MIPS_OFLAGS
        return _GENERIC_OFLAGS

    def _decode_flags(self, flags: int) -> tuple:
        accmode = flags & O_ACCMODE
        readable = accmode != O_WRONLY
        writable = accmode != O_RDONLY
        o_creat, o_trunc, o_append = self._option_flags()
        return (
            readable,
            writable,
            bool(flags & o_creat),
            bool(flags & o_trunc),
            bool(flags & o_append),
        )

    def _open_path(self, emulator: emulators.Emulator, ptr: int) -> str:
        length = _emu_strlen(emulator, ptr)
        return emulator.read_memory(ptr, length).decode("utf-8")

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        ptr = self.get_arg1(emulator)
        flags = self.get_arg2(emulator)
        assert isinstance(ptr, int)
        assert isinstance(flags, int)

        path = self._open_path(emulator, ptr)
        readable, writable, create, truncate, append = self._decode_flags(flags)

        try:
            fd = self._fdmgr.open(path, readable, writable, create, truncate, append)
        except FDIOError:
            logger.exception(f"Failed to open {path} (flags {flags:#x})")
            self.set_return_value(emulator, -1)
            return

        self.set_return_value(emulator, fd)


class Creat(Open):
    name = "creat"

    # int creat(const char *pathname, mode_t mode);
    #   equivalent to open(pathname, O_WRONLY | O_CREAT | O_TRUNC, mode).
    argument_types = [ArgumentType.POINTER, ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        # Deliberately skip Open.model (no flags to decode) and go straight to
        # the base model bookkeeping.
        FDModel.model(self, emulator)

        ptr = self.get_arg1(emulator)
        assert isinstance(ptr, int)
        path = self._open_path(emulator, ptr)

        try:
            fd = self._fdmgr.open(path, False, True, True, True, False)
        except FDIOError:
            logger.exception(f"Failed to creat {path}")
            self.set_return_value(emulator, -1)
            return

        self.set_return_value(emulator, fd)


__all__ = ["Open", "Creat"]
