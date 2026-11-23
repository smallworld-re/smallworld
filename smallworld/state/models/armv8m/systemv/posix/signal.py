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
from ..systemv import ArmV8MSysVModel


class ArmV8MSysVBsdSignal(BsdSignal, ArmV8MSysVModel):
    pass


class ArmV8MSysVKill(Kill, ArmV8MSysVModel):
    pass


class ArmV8MSysVKillpg(Killpg, ArmV8MSysVModel):
    pass


class ArmV8MSysVPthreadKill(PthreadKill, ArmV8MSysVModel):
    pass


class ArmV8MSysVPthreadSigmask(PthreadSigmask, ArmV8MSysVModel):
    pass


class ArmV8MSysVSigaction(Sigaction, ArmV8MSysVModel):
    pass


class ArmV8MSysVSigaddset(Sigaddset, ArmV8MSysVModel):
    pass


class ArmV8MSysVSigaltstack(Sigaltstack, ArmV8MSysVModel):
    pass


class ArmV8MSysVSigdelset(Sigdelset, ArmV8MSysVModel):
    pass


class ArmV8MSysVSigemptyset(Sigemptyset, ArmV8MSysVModel):
    pass


class ArmV8MSysVSigfillset(Sigfillset, ArmV8MSysVModel):
    pass


class ArmV8MSysVSighold(Sighold, ArmV8MSysVModel):
    pass


class ArmV8MSysVSigignore(Sigignore, ArmV8MSysVModel):
    pass


class ArmV8MSysVSiginterrupt(Siginterrupt, ArmV8MSysVModel):
    pass


class ArmV8MSysVSigismember(Sigismember, ArmV8MSysVModel):
    pass


class ArmV8MSysVSigpause(Sigpause, ArmV8MSysVModel):
    pass


class ArmV8MSysVSigpending(Sigpending, ArmV8MSysVModel):
    pass


class ArmV8MSysVSigprocmask(Sigprocmask, ArmV8MSysVModel):
    pass


class ArmV8MSysVSigqueue(Sigqueue, ArmV8MSysVModel):
    pass


class ArmV8MSysVSigrelse(Sigrelse, ArmV8MSysVModel):
    pass


class ArmV8MSysVSigset(Sigset, ArmV8MSysVModel):
    pass


class ArmV8MSysVSigsuspend(Sigsuspend, ArmV8MSysVModel):
    pass


class ArmV8MSysVSigtimedwait(Sigtimedwait, ArmV8MSysVModel):
    pass


class ArmV8MSysVSigwait(Sigwait, ArmV8MSysVModel):
    pass


class ArmV8MSysVSigwaitinfo(Sigwaitinfo, ArmV8MSysVModel):
    pass


__all__ = [
    "ArmV8MSysVBsdSignal",
    "ArmV8MSysVKill",
    "ArmV8MSysVKillpg",
    "ArmV8MSysVPthreadKill",
    "ArmV8MSysVPthreadSigmask",
    "ArmV8MSysVSigaction",
    "ArmV8MSysVSigaddset",
    "ArmV8MSysVSigaltstack",
    "ArmV8MSysVSigdelset",
    "ArmV8MSysVSigemptyset",
    "ArmV8MSysVSigfillset",
    "ArmV8MSysVSighold",
    "ArmV8MSysVSigignore",
    "ArmV8MSysVSiginterrupt",
    "ArmV8MSysVSigismember",
    "ArmV8MSysVSigpause",
    "ArmV8MSysVSigpending",
    "ArmV8MSysVSigprocmask",
    "ArmV8MSysVSigqueue",
    "ArmV8MSysVSigrelse",
    "ArmV8MSysVSigset",
    "ArmV8MSysVSigsuspend",
    "ArmV8MSysVSigtimedwait",
    "ArmV8MSysVSigwait",
    "ArmV8MSysVSigwaitinfo",
]
