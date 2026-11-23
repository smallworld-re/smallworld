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
from ..systemv import ArmV8ASysVModel


class ArmV8ASysVBsdSignal(BsdSignal, ArmV8ASysVModel):
    pass


class ArmV8ASysVKill(Kill, ArmV8ASysVModel):
    pass


class ArmV8ASysVKillpg(Killpg, ArmV8ASysVModel):
    pass


class ArmV8ASysVPthreadKill(PthreadKill, ArmV8ASysVModel):
    pass


class ArmV8ASysVPthreadSigmask(PthreadSigmask, ArmV8ASysVModel):
    pass


class ArmV8ASysVSigaction(Sigaction, ArmV8ASysVModel):
    pass


class ArmV8ASysVSigaddset(Sigaddset, ArmV8ASysVModel):
    pass


class ArmV8ASysVSigaltstack(Sigaltstack, ArmV8ASysVModel):
    pass


class ArmV8ASysVSigdelset(Sigdelset, ArmV8ASysVModel):
    pass


class ArmV8ASysVSigemptyset(Sigemptyset, ArmV8ASysVModel):
    pass


class ArmV8ASysVSigfillset(Sigfillset, ArmV8ASysVModel):
    pass


class ArmV8ASysVSighold(Sighold, ArmV8ASysVModel):
    pass


class ArmV8ASysVSigignore(Sigignore, ArmV8ASysVModel):
    pass


class ArmV8ASysVSiginterrupt(Siginterrupt, ArmV8ASysVModel):
    pass


class ArmV8ASysVSigismember(Sigismember, ArmV8ASysVModel):
    pass


class ArmV8ASysVSigpause(Sigpause, ArmV8ASysVModel):
    pass


class ArmV8ASysVSigpending(Sigpending, ArmV8ASysVModel):
    pass


class ArmV8ASysVSigprocmask(Sigprocmask, ArmV8ASysVModel):
    pass


class ArmV8ASysVSigqueue(Sigqueue, ArmV8ASysVModel):
    pass


class ArmV8ASysVSigrelse(Sigrelse, ArmV8ASysVModel):
    pass


class ArmV8ASysVSigset(Sigset, ArmV8ASysVModel):
    pass


class ArmV8ASysVSigsuspend(Sigsuspend, ArmV8ASysVModel):
    pass


class ArmV8ASysVSigtimedwait(Sigtimedwait, ArmV8ASysVModel):
    pass


class ArmV8ASysVSigwait(Sigwait, ArmV8ASysVModel):
    pass


class ArmV8ASysVSigwaitinfo(Sigwaitinfo, ArmV8ASysVModel):
    pass


__all__ = [
    "ArmV8ASysVBsdSignal",
    "ArmV8ASysVKill",
    "ArmV8ASysVKillpg",
    "ArmV8ASysVPthreadKill",
    "ArmV8ASysVPthreadSigmask",
    "ArmV8ASysVSigaction",
    "ArmV8ASysVSigaddset",
    "ArmV8ASysVSigaltstack",
    "ArmV8ASysVSigdelset",
    "ArmV8ASysVSigemptyset",
    "ArmV8ASysVSigfillset",
    "ArmV8ASysVSighold",
    "ArmV8ASysVSigignore",
    "ArmV8ASysVSiginterrupt",
    "ArmV8ASysVSigismember",
    "ArmV8ASysVSigpause",
    "ArmV8ASysVSigpending",
    "ArmV8ASysVSigprocmask",
    "ArmV8ASysVSigqueue",
    "ArmV8ASysVSigrelse",
    "ArmV8ASysVSigset",
    "ArmV8ASysVSigsuspend",
    "ArmV8ASysVSigtimedwait",
    "ArmV8ASysVSigwait",
    "ArmV8ASysVSigwaitinfo",
]
