from ..... import platforms
from ...armv5t.systemv.systemv import ArmV5TSysVCallingContext
from ...cstd import CStdModel
from ...posix.filedesc import POSIXFileDescriptorManager


class FileDescriptorManager(POSIXFileDescriptorManager):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V5T, platforms.Byteorder.BIG
    )
    abi = platforms.ABI.SYSTEMV


class ArmV5TBESysVCallingContext(ArmV5TSysVCallingContext):
    """The ARM GNU EABI on a big-endian (BE32) ARMv5t CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V5T, platforms.Byteorder.BIG
    )


class ArmV5TBESysVModel(ArmV5TBESysVCallingContext, CStdModel):
    """Base class for C models using the big-endian ARM32 GNU EABI"""

    pass
