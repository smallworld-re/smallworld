from ..... import platforms
from ...aarch64be.systemv.systemv import AArch64BESysVCallingContext
from ...cstd import CStdModel
from ...posix.filedesc import POSIXFileDescriptorManager


class FileDescriptorManager(POSIXFileDescriptorManager):
    platform = platforms.Platform(
        platforms.Architecture.AARCH64_V8_5A, platforms.Byteorder.BIG
    )
    abi = platforms.ABI.SYSTEMV


class AArch64V85ABESysVCallingContext(AArch64BESysVCallingContext):
    """The AArch64 System V ABI on a big-endian ARMv8.5-A CPU"""

    platform = platforms.Platform(
        platforms.Architecture.AARCH64_V8_5A, platforms.Byteorder.BIG
    )


class AArch64V85ABESysVModel(AArch64V85ABESysVCallingContext, CStdModel):
    """Base class for C models using the big-endian ARMv8.5-A AArch64 System V ABI"""

    pass
