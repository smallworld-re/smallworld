from ..... import platforms
from ...aarch64.systemv.systemv import AArch64SysVCallingContext
from ...cstd import CStdModel
from ...posix.filedesc import POSIXFileDescriptorManager


class FileDescriptorManager(POSIXFileDescriptorManager):
    platform = platforms.Platform(
        platforms.Architecture.AARCH64, platforms.Byteorder.BIG
    )
    abi = platforms.ABI.SYSTEMV


class AArch64BESysVCallingContext(AArch64SysVCallingContext):
    """The AArch64 System V ABI on a big-endian CPU"""

    platform = platforms.Platform(
        platforms.Architecture.AARCH64, platforms.Byteorder.BIG
    )


class AArch64BESysVModel(AArch64BESysVCallingContext, CStdModel):
    """Base class for C models using the big-endian AArch64 System V ABI"""

    pass
