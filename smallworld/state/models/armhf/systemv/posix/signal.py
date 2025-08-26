from ....posix.signal import (
    BsdSignal,
    Kill,
    Killpg,
    PthreadKill,
    PthreadSigmask,
    Sigaction,
    Sigaddset,
    Sigaltstack,
    Sigdelset,
    Sigemptyset,
    Sigfillset,
    Sighold,
    Sigignore,
    Siginterrupt,
    Sigismember,
    Sigpause,
    Sigpending,
    Sigprocmask,
    Sigqueue,
    Sigrelse,
    Sigset,
    Sigsuspend,
    Sigtimedwait,
    Sigwait,
    Sigwaitinfo,
)
from ..systemv import ArmHFSysVModel


class ArmHFSysVBsdSignal(BsdSignal, ArmHFSysVModel):
    pass


class ArmHFSysVKill(Kill, ArmHFSysVModel):
    pass


class ArmHFSysVKillpg(Killpg, ArmHFSysVModel):
    pass


class ArmHFSysVPthreadKill(PthreadKill, ArmHFSysVModel):
    pass


class ArmHFSysVPthreadSigmask(PthreadSigmask, ArmHFSysVModel):
    pass


class ArmHFSysVSigaction(Sigaction, ArmHFSysVModel):
    pass


class ArmHFSysVSigaddset(Sigaddset, ArmHFSysVModel):
    pass


class ArmHFSysVSigaltstack(Sigaltstack, ArmHFSysVModel):
    pass


class ArmHFSysVSigdelset(Sigdelset, ArmHFSysVModel):
    pass


class ArmHFSysVSigemptyset(Sigemptyset, ArmHFSysVModel):
    pass


class ArmHFSysVSigfillset(Sigfillset, ArmHFSysVModel):
    pass


class ArmHFSysVSighold(Sighold, ArmHFSysVModel):
    pass


class ArmHFSysVSigignore(Sigignore, ArmHFSysVModel):
    pass


class ArmHFSysVSiginterrupt(Siginterrupt, ArmHFSysVModel):
    pass


class ArmHFSysVSigismember(Sigismember, ArmHFSysVModel):
    pass


class ArmHFSysVSigpause(Sigpause, ArmHFSysVModel):
    pass


class ArmHFSysVSigpending(Sigpending, ArmHFSysVModel):
    pass


class ArmHFSysVSigprocmask(Sigprocmask, ArmHFSysVModel):
    pass


class ArmHFSysVSigqueue(Sigqueue, ArmHFSysVModel):
    pass


class ArmHFSysVSigrelse(Sigrelse, ArmHFSysVModel):
    pass


class ArmHFSysVSigset(Sigset, ArmHFSysVModel):
    pass


class ArmHFSysVSigsuspend(Sigsuspend, ArmHFSysVModel):
    pass


class ArmHFSysVSigtimedwait(Sigtimedwait, ArmHFSysVModel):
    pass


class ArmHFSysVSigwait(Sigwait, ArmHFSysVModel):
    pass


class ArmHFSysVSigwaitinfo(Sigwaitinfo, ArmHFSysVModel):
    pass


__all__ = [
    "ArmHFSysVBsdSignal",
    "ArmHFSysVKill",
    "ArmHFSysVKillpg",
    "ArmHFSysVPthreadKill",
    "ArmHFSysVPthreadSigmask",
    "ArmHFSysVSigaction",
    "ArmHFSysVSigaddset",
    "ArmHFSysVSigaltstack",
    "ArmHFSysVSigdelset",
    "ArmHFSysVSigemptyset",
    "ArmHFSysVSigfillset",
    "ArmHFSysVSighold",
    "ArmHFSysVSigignore",
    "ArmHFSysVSiginterrupt",
    "ArmHFSysVSigismember",
    "ArmHFSysVSigpause",
    "ArmHFSysVSigpending",
    "ArmHFSysVSigprocmask",
    "ArmHFSysVSigqueue",
    "ArmHFSysVSigrelse",
    "ArmHFSysVSigset",
    "ArmHFSysVSigsuspend",
    "ArmHFSysVSigtimedwait",
    "ArmHFSysVSigwait",
    "ArmHFSysVSigwaitinfo",
]
