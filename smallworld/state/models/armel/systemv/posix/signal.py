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
from ..systemv import ArmELSysVModel


class ArmELSysVBsdSignal(BsdSignal, ArmELSysVModel):
    pass


class ArmELSysVKill(Kill, ArmELSysVModel):
    pass


class ArmELSysVKillpg(Killpg, ArmELSysVModel):
    pass


class ArmELSysVPthreadKill(PthreadKill, ArmELSysVModel):
    pass


class ArmELSysVPthreadSigmask(PthreadSigmask, ArmELSysVModel):
    pass


class ArmELSysVSigaction(Sigaction, ArmELSysVModel):
    pass


class ArmELSysVSigaddset(Sigaddset, ArmELSysVModel):
    pass


class ArmELSysVSigaltstack(Sigaltstack, ArmELSysVModel):
    pass


class ArmELSysVSigdelset(Sigdelset, ArmELSysVModel):
    pass


class ArmELSysVSigemptyset(Sigemptyset, ArmELSysVModel):
    pass


class ArmELSysVSigfillset(Sigfillset, ArmELSysVModel):
    pass


class ArmELSysVSighold(Sighold, ArmELSysVModel):
    pass


class ArmELSysVSigignore(Sigignore, ArmELSysVModel):
    pass


class ArmELSysVSiginterrupt(Siginterrupt, ArmELSysVModel):
    pass


class ArmELSysVSigismember(Sigismember, ArmELSysVModel):
    pass


class ArmELSysVSigpause(Sigpause, ArmELSysVModel):
    pass


class ArmELSysVSigpending(Sigpending, ArmELSysVModel):
    pass


class ArmELSysVSigprocmask(Sigprocmask, ArmELSysVModel):
    pass


class ArmELSysVSigqueue(Sigqueue, ArmELSysVModel):
    pass


class ArmELSysVSigrelse(Sigrelse, ArmELSysVModel):
    pass


class ArmELSysVSigset(Sigset, ArmELSysVModel):
    pass


class ArmELSysVSigsuspend(Sigsuspend, ArmELSysVModel):
    pass


class ArmELSysVSigtimedwait(Sigtimedwait, ArmELSysVModel):
    pass


class ArmELSysVSigwait(Sigwait, ArmELSysVModel):
    pass


class ArmELSysVSigwaitinfo(Sigwaitinfo, ArmELSysVModel):
    pass


__all__ = [
    "ArmELSysVBsdSignal",
    "ArmELSysVKill",
    "ArmELSysVKillpg",
    "ArmELSysVPthreadKill",
    "ArmELSysVPthreadSigmask",
    "ArmELSysVSigaction",
    "ArmELSysVSigaddset",
    "ArmELSysVSigaltstack",
    "ArmELSysVSigdelset",
    "ArmELSysVSigemptyset",
    "ArmELSysVSigfillset",
    "ArmELSysVSighold",
    "ArmELSysVSigignore",
    "ArmELSysVSiginterrupt",
    "ArmELSysVSigismember",
    "ArmELSysVSigpause",
    "ArmELSysVSigpending",
    "ArmELSysVSigprocmask",
    "ArmELSysVSigqueue",
    "ArmELSysVSigrelse",
    "ArmELSysVSigset",
    "ArmELSysVSigsuspend",
    "ArmELSysVSigtimedwait",
    "ArmELSysVSigwait",
    "ArmELSysVSigwaitinfo",
]
