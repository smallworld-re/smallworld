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
from ..systemv import ArmV6MSysVModel


class ArmV6MSysVBsdSignal(BsdSignal, ArmV6MSysVModel):
    pass


class ArmV6MSysVKill(Kill, ArmV6MSysVModel):
    pass


class ArmV6MSysVKillpg(Killpg, ArmV6MSysVModel):
    pass


class ArmV6MSysVPthreadKill(PthreadKill, ArmV6MSysVModel):
    pass


class ArmV6MSysVPthreadSigmask(PthreadSigmask, ArmV6MSysVModel):
    pass


class ArmV6MSysVSigaction(Sigaction, ArmV6MSysVModel):
    pass


class ArmV6MSysVSigaddset(Sigaddset, ArmV6MSysVModel):
    pass


class ArmV6MSysVSigaltstack(Sigaltstack, ArmV6MSysVModel):
    pass


class ArmV6MSysVSigdelset(Sigdelset, ArmV6MSysVModel):
    pass


class ArmV6MSysVSigemptyset(Sigemptyset, ArmV6MSysVModel):
    pass


class ArmV6MSysVSigfillset(Sigfillset, ArmV6MSysVModel):
    pass


class ArmV6MSysVSighold(Sighold, ArmV6MSysVModel):
    pass


class ArmV6MSysVSigignore(Sigignore, ArmV6MSysVModel):
    pass


class ArmV6MSysVSiginterrupt(Siginterrupt, ArmV6MSysVModel):
    pass


class ArmV6MSysVSigismember(Sigismember, ArmV6MSysVModel):
    pass


class ArmV6MSysVSigpause(Sigpause, ArmV6MSysVModel):
    pass


class ArmV6MSysVSigpending(Sigpending, ArmV6MSysVModel):
    pass


class ArmV6MSysVSigprocmask(Sigprocmask, ArmV6MSysVModel):
    pass


class ArmV6MSysVSigqueue(Sigqueue, ArmV6MSysVModel):
    pass


class ArmV6MSysVSigrelse(Sigrelse, ArmV6MSysVModel):
    pass


class ArmV6MSysVSigset(Sigset, ArmV6MSysVModel):
    pass


class ArmV6MSysVSigsuspend(Sigsuspend, ArmV6MSysVModel):
    pass


class ArmV6MSysVSigtimedwait(Sigtimedwait, ArmV6MSysVModel):
    pass


class ArmV6MSysVSigwait(Sigwait, ArmV6MSysVModel):
    pass


class ArmV6MSysVSigwaitinfo(Sigwaitinfo, ArmV6MSysVModel):
    pass


__all__ = [
    "ArmV6MSysVBsdSignal",
    "ArmV6MSysVKill",
    "ArmV6MSysVKillpg",
    "ArmV6MSysVPthreadKill",
    "ArmV6MSysVPthreadSigmask",
    "ArmV6MSysVSigaction",
    "ArmV6MSysVSigaddset",
    "ArmV6MSysVSigaltstack",
    "ArmV6MSysVSigdelset",
    "ArmV6MSysVSigemptyset",
    "ArmV6MSysVSigfillset",
    "ArmV6MSysVSighold",
    "ArmV6MSysVSigignore",
    "ArmV6MSysVSiginterrupt",
    "ArmV6MSysVSigismember",
    "ArmV6MSysVSigpause",
    "ArmV6MSysVSigpending",
    "ArmV6MSysVSigprocmask",
    "ArmV6MSysVSigqueue",
    "ArmV6MSysVSigrelse",
    "ArmV6MSysVSigset",
    "ArmV6MSysVSigsuspend",
    "ArmV6MSysVSigtimedwait",
    "ArmV6MSysVSigwait",
    "ArmV6MSysVSigwaitinfo",
]
