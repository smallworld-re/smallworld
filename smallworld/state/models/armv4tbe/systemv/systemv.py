from ..... import platforms
from ...armv4t.systemv.systemv import ArmV4TSysVCallingContext
from ...cstd import CStdModel
from ...posix.filedesc import POSIXFileDescriptorManager


class FileDescriptorManager(POSIXFileDescriptorManager):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V4T, platforms.Byteorder.BIG
    )
    abi = platforms.ABI.SYSTEMV


class ArmV4TBESysVCallingContext(ArmV4TSysVCallingContext):
    """The ARM GNU EABI on a big-endian (BE32) ARMv4t CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V4T, platforms.Byteorder.BIG
    )


class ArmV4TBESysVModel(ArmV4TBESysVCallingContext, CStdModel):
    """Base class for C models using the big-endian ARM32 GNU EABI"""

    pass
