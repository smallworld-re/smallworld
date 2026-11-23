from ..... import platforms
from ...armv7a.systemv.systemv import ArmV7ASysVCallingContext
from ...cstd import CStdModel
from ...posix.filedesc import POSIXFileDescriptorManager


class FileDescriptorManager(POSIXFileDescriptorManager):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V7A, platforms.Byteorder.BIG
    )
    abi = platforms.ABI.SYSTEMV


class ArmV7ABESysVCallingContext(ArmV7ASysVCallingContext):
    """The ARM GNU EABI on a big-endian (BE8) ARMv7-A CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V7A, platforms.Byteorder.BIG
    )


class ArmV7ABESysVModel(ArmV7ABESysVCallingContext, CStdModel):
    """Base class for C models using the big-endian ARM32 GNU EABI"""

    pass
