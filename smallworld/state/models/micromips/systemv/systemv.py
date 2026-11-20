# microMIPS code uses MIPS32's o32 calling convention unchanged, so these
# are the models/mips classes, for the microMIPS platform.
from ..... import platforms
from ...cstd import CStdModel
from ...mips.systemv.systemv import FileDescriptorManager as MIPSFileDescriptorManager
from ...mips.systemv.systemv import MIPSSysVCallingContext


class FileDescriptorManager(MIPSFileDescriptorManager):
    platform = platforms.Platform(
        platforms.Architecture.MIPS32_MICROMIPS, platforms.Byteorder.BIG
    )


class MicroMIPSSysVCallingContext(MIPSSysVCallingContext):
    platform = platforms.Platform(
        platforms.Architecture.MIPS32_MICROMIPS, platforms.Byteorder.BIG
    )


class MicroMIPSSysVModel(MicroMIPSSysVCallingContext, CStdModel):
    """Base class for C models using the MIPS o32 ABI, on microMIPS"""

    pass
