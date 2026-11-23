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
from ..systemv import ArmV7EMSysVModel


class ArmV7EMSysVBsdSignal(BsdSignal, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVKill(Kill, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVKillpg(Killpg, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVPthreadKill(PthreadKill, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVPthreadSigmask(PthreadSigmask, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSigaction(Sigaction, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSigaddset(Sigaddset, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSigaltstack(Sigaltstack, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSigdelset(Sigdelset, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSigemptyset(Sigemptyset, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSigfillset(Sigfillset, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSighold(Sighold, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSigignore(Sigignore, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSiginterrupt(Siginterrupt, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSigismember(Sigismember, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSigpause(Sigpause, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSigpending(Sigpending, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSigprocmask(Sigprocmask, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSigqueue(Sigqueue, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSigrelse(Sigrelse, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSigset(Sigset, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSigsuspend(Sigsuspend, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSigtimedwait(Sigtimedwait, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSigwait(Sigwait, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSigwaitinfo(Sigwaitinfo, ArmV7EMSysVModel):
    pass


__all__ = [
    "ArmV7EMSysVBsdSignal",
    "ArmV7EMSysVKill",
    "ArmV7EMSysVKillpg",
    "ArmV7EMSysVPthreadKill",
    "ArmV7EMSysVPthreadSigmask",
    "ArmV7EMSysVSigaction",
    "ArmV7EMSysVSigaddset",
    "ArmV7EMSysVSigaltstack",
    "ArmV7EMSysVSigdelset",
    "ArmV7EMSysVSigemptyset",
    "ArmV7EMSysVSigfillset",
    "ArmV7EMSysVSighold",
    "ArmV7EMSysVSigignore",
    "ArmV7EMSysVSiginterrupt",
    "ArmV7EMSysVSigismember",
    "ArmV7EMSysVSigpause",
    "ArmV7EMSysVSigpending",
    "ArmV7EMSysVSigprocmask",
    "ArmV7EMSysVSigqueue",
    "ArmV7EMSysVSigrelse",
    "ArmV7EMSysVSigset",
    "ArmV7EMSysVSigsuspend",
    "ArmV7EMSysVSigtimedwait",
    "ArmV7EMSysVSigwait",
    "ArmV7EMSysVSigwaitinfo",
]
