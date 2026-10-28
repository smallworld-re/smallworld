from ..... import platforms
from ...armv8a.systemv.systemv import ArmV8ASysVCallingContext
from ...cstd import CStdModel
from ...posix.filedesc import POSIXFileDescriptorManager


class FileDescriptorManager(POSIXFileDescriptorManager):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V8A, platforms.Byteorder.BIG
    )
    abi = platforms.ABI.SYSTEMV


class ArmV8ABESysVCallingContext(ArmV8ASysVCallingContext):
    """The ARM GNU EABI on a big-endian (BE8) ARMv8-A CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V8A, platforms.Byteorder.BIG
    )


class ArmV8ABESysVModel(ArmV8ABESysVCallingContext, CStdModel):
    """Base class for C models using the big-endian ARM32 GNU EABI"""

    pass
