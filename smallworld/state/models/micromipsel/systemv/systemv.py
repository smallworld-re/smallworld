# microMIPS code uses MIPS32's o32 calling convention unchanged, so these
# are the models/mipsel classes, for the microMIPS platform.
from ..... import platforms
from ...cstd import CStdModel
from ...mipsel.systemv.systemv import (
    FileDescriptorManager as MIPSELFileDescriptorManager,
)
from ...mipsel.systemv.systemv import (
    MIPSELSysVCallingContext,
)


class FileDescriptorManager(MIPSELFileDescriptorManager):
    platform = platforms.Platform(
        platforms.Architecture.MIPS32_MICROMIPS, platforms.Byteorder.LITTLE
    )


class MicroMIPSELSysVCallingContext(MIPSELSysVCallingContext):
    platform = platforms.Platform(
        platforms.Architecture.MIPS32_MICROMIPS, platforms.Byteorder.LITTLE
    )


class MicroMIPSELSysVModel(MicroMIPSELSysVCallingContext, CStdModel):
    """Base class for C models using the MIPS o32 ABI, on microMIPS"""

    pass
