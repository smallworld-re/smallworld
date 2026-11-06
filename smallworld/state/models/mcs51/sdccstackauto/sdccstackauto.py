from ..... import platforms
from ..sdcc.sdcc import _ON_STACK
from ..sdcc.sdcc import FileDescriptorManager as SDCCFileDescriptorManager
from ..sdcc.sdcc import MCS51SDCCCallingContext, MCS51SDCCModel


class FileDescriptorManager(SDCCFileDescriptorManager):
    abi = platforms.ABI.SDCCSTACKAUTO


class MCS51SDCCStackAutoCallingContext(MCS51SDCCCallingContext):
    """SDCC's reentrant calling convention for the 8051.

    What ``--stack-auto`` compiles every function to, and ``__reentrant``
    one function.  As SDCC's default convention (see
    :class:`MCS51SDCCCallingContext`), except that arguments after the first
    go on the stack: pushed last to first, each little-endian, below the
    return address.  The caller pops them.
    """

    abi = platforms.ABI.SDCCSTACKAUTO

    _later_arguments = _ON_STACK


class MCS51SDCCStackAutoModel(MCS51SDCCStackAutoCallingContext, MCS51SDCCModel):
    """Base class for C models using SDCC's reentrant 8051 convention"""


__all__ = [
    "FileDescriptorManager",
    "MCS51SDCCStackAutoCallingContext",
    "MCS51SDCCStackAutoModel",
]
