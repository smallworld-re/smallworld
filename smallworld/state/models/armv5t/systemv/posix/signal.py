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
from ..systemv import ArmV5TSysVModel


class ArmV5TSysVBsdSignal(BsdSignal, ArmV5TSysVModel):
    pass


class ArmV5TSysVKill(Kill, ArmV5TSysVModel):
    pass


class ArmV5TSysVKillpg(Killpg, ArmV5TSysVModel):
    pass


class ArmV5TSysVPthreadKill(PthreadKill, ArmV5TSysVModel):
    pass


class ArmV5TSysVPthreadSigmask(PthreadSigmask, ArmV5TSysVModel):
    pass


class ArmV5TSysVSigaction(Sigaction, ArmV5TSysVModel):
    pass


class ArmV5TSysVSigaddset(Sigaddset, ArmV5TSysVModel):
    pass


class ArmV5TSysVSigaltstack(Sigaltstack, ArmV5TSysVModel):
    pass


class ArmV5TSysVSigdelset(Sigdelset, ArmV5TSysVModel):
    pass


class ArmV5TSysVSigemptyset(Sigemptyset, ArmV5TSysVModel):
    pass


class ArmV5TSysVSigfillset(Sigfillset, ArmV5TSysVModel):
    pass


class ArmV5TSysVSighold(Sighold, ArmV5TSysVModel):
    pass


class ArmV5TSysVSigignore(Sigignore, ArmV5TSysVModel):
    pass


class ArmV5TSysVSiginterrupt(Siginterrupt, ArmV5TSysVModel):
    pass


class ArmV5TSysVSigismember(Sigismember, ArmV5TSysVModel):
    pass


class ArmV5TSysVSigpause(Sigpause, ArmV5TSysVModel):
    pass


class ArmV5TSysVSigpending(Sigpending, ArmV5TSysVModel):
    pass


class ArmV5TSysVSigprocmask(Sigprocmask, ArmV5TSysVModel):
    pass


class ArmV5TSysVSigqueue(Sigqueue, ArmV5TSysVModel):
    pass


class ArmV5TSysVSigrelse(Sigrelse, ArmV5TSysVModel):
    pass


class ArmV5TSysVSigset(Sigset, ArmV5TSysVModel):
    pass


class ArmV5TSysVSigsuspend(Sigsuspend, ArmV5TSysVModel):
    pass


class ArmV5TSysVSigtimedwait(Sigtimedwait, ArmV5TSysVModel):
    pass


class ArmV5TSysVSigwait(Sigwait, ArmV5TSysVModel):
    pass


class ArmV5TSysVSigwaitinfo(Sigwaitinfo, ArmV5TSysVModel):
    pass


__all__ = [
    "ArmV5TSysVBsdSignal",
    "ArmV5TSysVKill",
    "ArmV5TSysVKillpg",
    "ArmV5TSysVPthreadKill",
    "ArmV5TSysVPthreadSigmask",
    "ArmV5TSysVSigaction",
    "ArmV5TSysVSigaddset",
    "ArmV5TSysVSigaltstack",
    "ArmV5TSysVSigdelset",
    "ArmV5TSysVSigemptyset",
    "ArmV5TSysVSigfillset",
    "ArmV5TSysVSighold",
    "ArmV5TSysVSigignore",
    "ArmV5TSysVSiginterrupt",
    "ArmV5TSysVSigismember",
    "ArmV5TSysVSigpause",
    "ArmV5TSysVSigpending",
    "ArmV5TSysVSigprocmask",
    "ArmV5TSysVSigqueue",
    "ArmV5TSysVSigrelse",
    "ArmV5TSysVSigset",
    "ArmV5TSysVSigsuspend",
    "ArmV5TSysVSigtimedwait",
    "ArmV5TSysVSigwait",
    "ArmV5TSysVSigwaitinfo",
]
