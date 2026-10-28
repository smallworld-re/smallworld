from ..... import platforms
from ...armel.systemv.systemv import ArmELSysVCallingContext
from ...cstd import CStdModel
from ...posix.filedesc import POSIXFileDescriptorManager


class FileDescriptorManager(POSIXFileDescriptorManager):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V6K, platforms.Byteorder.BIG
    )
    abi = platforms.ABI.SYSTEMV


class ArmV6KBESysVCallingContext(ArmELSysVCallingContext):
    """The ARM GNU EABI on a big-endian (BE8) ARMv6K CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V6K, platforms.Byteorder.BIG
    )


class ArmV6KBESysVModel(ArmV6KBESysVCallingContext, CStdModel):
    """Base class for C models using the big-endian ARM32 GNU EABI"""

    pass
