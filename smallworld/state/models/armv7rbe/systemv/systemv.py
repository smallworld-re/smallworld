from ..... import platforms
from ...armv7r.systemv.systemv import ArmV7RSysVCallingContext
from ...cstd import CStdModel
from ...posix.filedesc import POSIXFileDescriptorManager


class FileDescriptorManager(POSIXFileDescriptorManager):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V7R, platforms.Byteorder.BIG
    )
    abi = platforms.ABI.SYSTEMV


class ArmV7RBESysVCallingContext(ArmV7RSysVCallingContext):
    """The ARM GNU EABI on a big-endian (BE8) ARMv7-R CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V7R, platforms.Byteorder.BIG
    )


class ArmV7RBESysVModel(ArmV7RBESysVCallingContext, CStdModel):
    """Base class for C models using the big-endian ARM32 GNU EABI"""

    pass
