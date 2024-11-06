from .... import platforms
from ..model import Model
from ..posix import (
    BasenameModel,
    CallocModel,
    DaemonModel,
    FlockModel,
    Getopt_longModel,
    GetpagesizeModel,
    GetppidModel,
    GetsModel,
    MallocModel,
    Open64Model,
    OpenModel,
    PthreadCondInitModel,
    PthreadCondSignalModel,
    PthreadCondWaitModel,
    PthreadCreateModel,
    PthreadMutexInitModel,
    PthreadMutexLockModel,
    PthreadMutexUnlockModel,
    PtraceModel,
    PutsModel,
    RandModel,
    RandomModel,
    SleepModel,
    SrandModel,
    SrandomModel,
    StrcatModel,
    StrcpyModel,
    StrdupModel,
    StrlenModel,
    StrncatModel,
    StrncpyModel,
    StrnlenModel,
    SysconfModel,
    TimeModel,
    UnlinkModel,
    WriteModel,
)


class AMD64SystemVModel(Model):
    platform = platforms.Platform(
        platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
    )

    abi = platforms.ABI.SYSTEMV

    argument1 = "rdi"
    argument2 = "rsi"
    argument3 = "rdx"
    argument4 = "rcx"
    argument5 = "r8"
    argument6 = "r9"
    return_val = "rax"


class AMD64SystemVBasenameModel(AMD64SystemVModel, BasenameModel):
    pass


class AMD64SystemVCallocModel(AMD64SystemVModel, CallocModel):
    pass


class AMD64SystemVDaemonModel(AMD64SystemVModel, DaemonModel):
    pass


class AMD64SystemVFlockModel(AMD64SystemVModel, FlockModel):
    pass


class AMD64SystemVGetopt_longModel(AMD64SystemVModel, Getopt_longModel):
    pass


class AMD64SystemVGetpagesizeModel(AMD64SystemVModel, GetpagesizeModel):
    pass


class AMD64SystemVGetppidModel(AMD64SystemVModel, GetppidModel):
    pass


class AMD64SystemVGetsModel(AMD64SystemVModel, GetsModel):
    pass


class AMD64SystemVMallocModel(AMD64SystemVModel, MallocModel):
    pass


class AMD64SystemVOpenModel(AMD64SystemVModel, OpenModel):
    pass


class AMD64SystemVOpen64Model(AMD64SystemVModel, Open64Model):
    pass


class AMD64SystemVPutsModel(AMD64SystemVModel, PutsModel):
    pass


class AMD64SystemVPthreadCondInitModel(AMD64SystemVModel, PthreadCondInitModel):
    pass


class AMD64SystemVPthreadCondSignalModel(AMD64SystemVModel, PthreadCondSignalModel):
    pass


class AMD64SystemVPthreadCondWaitModel(AMD64SystemVModel, PthreadCondWaitModel):
    pass


class AMD64SystemVPthreadCreateModel(AMD64SystemVModel, PthreadCreateModel):
    pass


class AMD64SystemVPthreadMutexInitModel(AMD64SystemVModel, PthreadMutexInitModel):
    pass


class AMD64SystemVPthreadMutexLockModel(AMD64SystemVModel, PthreadMutexLockModel):
    pass


class AMD64SystemVPthreadMutexUnlockModel(AMD64SystemVModel, PthreadMutexUnlockModel):
    pass


class AMD64SystemVPtraceModel(AMD64SystemVModel, PtraceModel):
    pass


class AMD64SystemVRandModel(AMD64SystemVModel, RandModel):
    pass


class AMD64SystemVRandomModel(AMD64SystemVModel, RandomModel):
    pass


class AMD64SystemVSleepModel(AMD64SystemVModel, SleepModel):
    pass


class AMD64SystemVSrandModel(AMD64SystemVModel, SrandModel):
    pass


class AMD64SystemVSrandomModel(AMD64SystemVModel, SrandomModel):
    pass


class AMD64SystemVStrcatModel(AMD64SystemVModel, StrcatModel):
    pass


class AMD64SystemVStrncatModel(AMD64SystemVModel, StrncatModel):
    pass


class AMD64SystemVStrcpyModel(AMD64SystemVModel, StrcpyModel):
    pass


class AMD64SystemVStrncpyModel(AMD64SystemVModel, StrncpyModel):
    pass


class AMD64SystemVStrdupModel(AMD64SystemVModel, StrdupModel):
    pass


class AMD64SystemVStrlenModel(AMD64SystemVModel, StrlenModel):
    pass


class AMD64SystemVStrnlenModel(AMD64SystemVModel, StrnlenModel):
    pass


class AMD64SystemVSysconfModel(AMD64SystemVModel, SysconfModel):
    pass


class AMD64SystemVTimeModel(AMD64SystemVModel, TimeModel):
    pass


class AMD64SystemVUnlinkModel(AMD64SystemVModel, UnlinkModel):
    pass


class AMD64SystemVWriteModel(AMD64SystemVModel, WriteModel):
    pass


__all__ = [
    "AMD64SystemVBasenameModel",
    "AMD64SystemVCallocModel",
    "AMD64SystemVDaemonModel",
    "AMD64SystemVFlockModel",
    "AMD64SystemVGetopt_longModel",
    "AMD64SystemVGetpagesizeModel",
    "AMD64SystemVGetppidModel",
    "AMD64SystemVGetsModel",
    "AMD64SystemVMallocModel",
    "AMD64SystemVOpenModel",
    "AMD64SystemVOpen64Model",
    "AMD64SystemVPutsModel",
    "AMD64SystemVPthreadCondInitModel",
    "AMD64SystemVPthreadCondSignalModel",
    "AMD64SystemVPthreadCondWaitModel",
    "AMD64SystemVPthreadCreateModel",
    "AMD64SystemVPthreadMutexInitModel",
    "AMD64SystemVPthreadMutexLockModel",
    "AMD64SystemVPthreadMutexUnlockModel",
    "AMD64SystemVPtraceModel",
    "AMD64SystemVRandModel",
    "AMD64SystemVRandomModel",
    "AMD64SystemVSleepModel",
    "AMD64SystemVSrandModel",
    "AMD64SystemVSrandomModel",
    "AMD64SystemVStrcatModel",
    "AMD64SystemVStrncatModel",
    "AMD64SystemVStrcpyModel",
    "AMD64SystemVStrncpyModel",
    "AMD64SystemVStrdupModel",
    "AMD64SystemVStrlenModel",
    "AMD64SystemVStrnlenModel",
    "AMD64SystemVSysconfModel",
    "AMD64SystemVTimeModel",
    "AMD64SystemVUnlinkModel",
    "AMD64SystemVWriteModel",
]
