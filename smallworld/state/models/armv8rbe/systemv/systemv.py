from ..... import platforms
from ...armv8r.systemv.systemv import ArmV8RSysVCallingContext
from ...cstd import CStdModel
from ...posix.filedesc import POSIXFileDescriptorManager


class FileDescriptorManager(POSIXFileDescriptorManager):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V8R, platforms.Byteorder.BIG
    )
    abi = platforms.ABI.SYSTEMV


class ArmV8RBESysVCallingContext(ArmV8RSysVCallingContext):
    """The ARM GNU EABI on a big-endian (BE8) ARMv8-R CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V8R, platforms.Byteorder.BIG
    )


class ArmV8RBESysVModel(ArmV8RBESysVCallingContext, CStdModel):
    """Base class for C models using the big-endian ARM32 GNU EABI"""

    pass
