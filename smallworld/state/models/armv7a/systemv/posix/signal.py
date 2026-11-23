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
from ..systemv import ArmV7ASysVModel


class ArmV7ASysVBsdSignal(BsdSignal, ArmV7ASysVModel):
    pass


class ArmV7ASysVKill(Kill, ArmV7ASysVModel):
    pass


class ArmV7ASysVKillpg(Killpg, ArmV7ASysVModel):
    pass


class ArmV7ASysVPthreadKill(PthreadKill, ArmV7ASysVModel):
    pass


class ArmV7ASysVPthreadSigmask(PthreadSigmask, ArmV7ASysVModel):
    pass


class ArmV7ASysVSigaction(Sigaction, ArmV7ASysVModel):
    pass


class ArmV7ASysVSigaddset(Sigaddset, ArmV7ASysVModel):
    pass


class ArmV7ASysVSigaltstack(Sigaltstack, ArmV7ASysVModel):
    pass


class ArmV7ASysVSigdelset(Sigdelset, ArmV7ASysVModel):
    pass


class ArmV7ASysVSigemptyset(Sigemptyset, ArmV7ASysVModel):
    pass


class ArmV7ASysVSigfillset(Sigfillset, ArmV7ASysVModel):
    pass


class ArmV7ASysVSighold(Sighold, ArmV7ASysVModel):
    pass


class ArmV7ASysVSigignore(Sigignore, ArmV7ASysVModel):
    pass


class ArmV7ASysVSiginterrupt(Siginterrupt, ArmV7ASysVModel):
    pass


class ArmV7ASysVSigismember(Sigismember, ArmV7ASysVModel):
    pass


class ArmV7ASysVSigpause(Sigpause, ArmV7ASysVModel):
    pass


class ArmV7ASysVSigpending(Sigpending, ArmV7ASysVModel):
    pass


class ArmV7ASysVSigprocmask(Sigprocmask, ArmV7ASysVModel):
    pass


class ArmV7ASysVSigqueue(Sigqueue, ArmV7ASysVModel):
    pass


class ArmV7ASysVSigrelse(Sigrelse, ArmV7ASysVModel):
    pass


class ArmV7ASysVSigset(Sigset, ArmV7ASysVModel):
    pass


class ArmV7ASysVSigsuspend(Sigsuspend, ArmV7ASysVModel):
    pass


class ArmV7ASysVSigtimedwait(Sigtimedwait, ArmV7ASysVModel):
    pass


class ArmV7ASysVSigwait(Sigwait, ArmV7ASysVModel):
    pass


class ArmV7ASysVSigwaitinfo(Sigwaitinfo, ArmV7ASysVModel):
    pass


__all__ = [
    "ArmV7ASysVBsdSignal",
    "ArmV7ASysVKill",
    "ArmV7ASysVKillpg",
    "ArmV7ASysVPthreadKill",
    "ArmV7ASysVPthreadSigmask",
    "ArmV7ASysVSigaction",
    "ArmV7ASysVSigaddset",
    "ArmV7ASysVSigaltstack",
    "ArmV7ASysVSigdelset",
    "ArmV7ASysVSigemptyset",
    "ArmV7ASysVSigfillset",
    "ArmV7ASysVSighold",
    "ArmV7ASysVSigignore",
    "ArmV7ASysVSiginterrupt",
    "ArmV7ASysVSigismember",
    "ArmV7ASysVSigpause",
    "ArmV7ASysVSigpending",
    "ArmV7ASysVSigprocmask",
    "ArmV7ASysVSigqueue",
    "ArmV7ASysVSigrelse",
    "ArmV7ASysVSigset",
    "ArmV7ASysVSigsuspend",
    "ArmV7ASysVSigtimedwait",
    "ArmV7ASysVSigwait",
    "ArmV7ASysVSigwaitinfo",
]
