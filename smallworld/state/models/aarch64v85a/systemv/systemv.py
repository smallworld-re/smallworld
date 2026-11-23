from ..... import platforms
from ...aarch64.systemv.systemv import AArch64SysVCallingContext
from ...cstd import CStdModel
from ...posix.filedesc import POSIXFileDescriptorManager


class FileDescriptorManager(POSIXFileDescriptorManager):
    platform = platforms.Platform(
        platforms.Architecture.AARCH64_V8_5A, platforms.Byteorder.LITTLE
    )
    abi = platforms.ABI.SYSTEMV


class AArch64V85ASysVCallingContext(AArch64SysVCallingContext):
    """The AArch64 System V ABI on an ARMv8.5-A CPU"""

    platform = platforms.Platform(
        platforms.Architecture.AARCH64_V8_5A, platforms.Byteorder.LITTLE
    )


class AArch64V85ASysVModel(AArch64V85ASysVCallingContext, CStdModel):
    """Base class for C models using the AArch64 System V ABI on ARMv8.5-A"""

    pass
