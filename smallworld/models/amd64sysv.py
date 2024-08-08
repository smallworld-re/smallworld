from .. import state
from .posix import (
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


class AMD64SystemVImplementedModel(state.models.ImplementedModel):
    arch = "x86"
    mode = "64"
    byteorder = "little"
    abi = "sysv"

    argument1 = "rdi"
    argument2 = "rsi"
    argument3 = "rdx"
    argument4 = "rcx"
    argument5 = "r8"
    argument6 = "r9"
    return_val = "rax"


class AMD64SystemVBasenameModel(AMD64SystemVImplementedModel, BasenameModel):
    pass


class AMD64SystemVCallocModel(AMD64SystemVImplementedModel, CallocModel):
    pass


class AMD64SystemVDaemonModel(AMD64SystemVImplementedModel, DaemonModel):
    pass


class AMD64SystemVFlockModel(AMD64SystemVImplementedModel, FlockModel):
    pass


class AMD64SystemVGetopt_longModel(AMD64SystemVImplementedModel, Getopt_longModel):
    pass


class AMD64SystemVGetpagesizeModel(AMD64SystemVImplementedModel, GetpagesizeModel):
    pass


class AMD64SystemVGetppidModel(AMD64SystemVImplementedModel, GetppidModel):
    pass


class AMD64SystemVGetsModel(AMD64SystemVImplementedModel, GetsModel):
    pass


class AMD64SystemVMallocModel(AMD64SystemVImplementedModel, MallocModel):
    pass


class AMD64SystemVOpenModel(AMD64SystemVImplementedModel, OpenModel):
    pass


class AMD64SystemVOpen64Model(AMD64SystemVImplementedModel, Open64Model):
    pass


class AMD64SystemVPutsModel(AMD64SystemVImplementedModel, PutsModel):
    pass


class AMD64SystemVPthreadCondInitModel(
    AMD64SystemVImplementedModel, PthreadCondInitModel
):
    pass


class AMD64SystemVPthreadCondSignalModel(
    AMD64SystemVImplementedModel, PthreadCondSignalModel
):
    pass


class AMD64SystemVPthreadCondWaitModel(
    AMD64SystemVImplementedModel, PthreadCondWaitModel
):
    pass


class AMD64SystemVPthreadCreateModel(AMD64SystemVImplementedModel, PthreadCreateModel):
    pass


class AMD64SystemVPthreadMutexInitModel(
    AMD64SystemVImplementedModel, PthreadMutexInitModel
):
    pass


class AMD64SystemVPthreadMutexLockModel(
    AMD64SystemVImplementedModel, PthreadMutexLockModel
):
    pass


class AMD64SystemVPthreadMutexUnlockModel(
    AMD64SystemVImplementedModel, PthreadMutexUnlockModel
):
    pass


class AMD64SystemVPtraceModel(AMD64SystemVImplementedModel, PtraceModel):
    pass


class AMD64SystemVRandModel(AMD64SystemVImplementedModel, RandModel):
    pass


class AMD64SystemVRandomModel(AMD64SystemVImplementedModel, RandomModel):
    pass


class AMD64SystemVSleepModel(AMD64SystemVImplementedModel, SleepModel):
    pass


class AMD64SystemVSrandModel(AMD64SystemVImplementedModel, SrandModel):
    pass


class AMD64SystemVSrandomModel(AMD64SystemVImplementedModel, SrandomModel):
    pass


class AMD64SystemVStrcatModel(AMD64SystemVImplementedModel, StrcatModel):
    pass


class AMD64SystemVStrncatModel(AMD64SystemVImplementedModel, StrncatModel):
    pass


class AMD64SystemVStrcpyModel(AMD64SystemVImplementedModel, StrcpyModel):
    pass


class AMD64SystemVStrncpyModel(AMD64SystemVImplementedModel, StrncpyModel):
    pass


class AMD64SystemVStrdupModel(AMD64SystemVImplementedModel, StrdupModel):
    pass


class AMD64SystemVStrlenModel(AMD64SystemVImplementedModel, StrlenModel):
    pass


class AMD64SystemVStrnlenModel(AMD64SystemVImplementedModel, StrnlenModel):
    pass


class AMD64SystemVSysconfModel(AMD64SystemVImplementedModel, SysconfModel):
    pass


class AMD64SystemVTimeModel(AMD64SystemVImplementedModel, TimeModel):
    pass


class AMD64SystemVUnlinkModel(AMD64SystemVImplementedModel, UnlinkModel):
    pass


class AMD64SystemVWriteModel(AMD64SystemVImplementedModel, WriteModel):
    pass


class AMD64SystemVNullModel(
    AMD64SystemVImplementedModel, state.models.Returns0ImplementedModel
):
    name = "null"
