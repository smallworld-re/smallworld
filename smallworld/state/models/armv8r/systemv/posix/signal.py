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
from ..systemv import ArmV8RSysVModel


class ArmV8RSysVBsdSignal(BsdSignal, ArmV8RSysVModel):
    pass


class ArmV8RSysVKill(Kill, ArmV8RSysVModel):
    pass


class ArmV8RSysVKillpg(Killpg, ArmV8RSysVModel):
    pass


class ArmV8RSysVPthreadKill(PthreadKill, ArmV8RSysVModel):
    pass


class ArmV8RSysVPthreadSigmask(PthreadSigmask, ArmV8RSysVModel):
    pass


class ArmV8RSysVSigaction(Sigaction, ArmV8RSysVModel):
    pass


class ArmV8RSysVSigaddset(Sigaddset, ArmV8RSysVModel):
    pass


class ArmV8RSysVSigaltstack(Sigaltstack, ArmV8RSysVModel):
    pass


class ArmV8RSysVSigdelset(Sigdelset, ArmV8RSysVModel):
    pass


class ArmV8RSysVSigemptyset(Sigemptyset, ArmV8RSysVModel):
    pass


class ArmV8RSysVSigfillset(Sigfillset, ArmV8RSysVModel):
    pass


class ArmV8RSysVSighold(Sighold, ArmV8RSysVModel):
    pass


class ArmV8RSysVSigignore(Sigignore, ArmV8RSysVModel):
    pass


class ArmV8RSysVSiginterrupt(Siginterrupt, ArmV8RSysVModel):
    pass


class ArmV8RSysVSigismember(Sigismember, ArmV8RSysVModel):
    pass


class ArmV8RSysVSigpause(Sigpause, ArmV8RSysVModel):
    pass


class ArmV8RSysVSigpending(Sigpending, ArmV8RSysVModel):
    pass


class ArmV8RSysVSigprocmask(Sigprocmask, ArmV8RSysVModel):
    pass


class ArmV8RSysVSigqueue(Sigqueue, ArmV8RSysVModel):
    pass


class ArmV8RSysVSigrelse(Sigrelse, ArmV8RSysVModel):
    pass


class ArmV8RSysVSigset(Sigset, ArmV8RSysVModel):
    pass


class ArmV8RSysVSigsuspend(Sigsuspend, ArmV8RSysVModel):
    pass


class ArmV8RSysVSigtimedwait(Sigtimedwait, ArmV8RSysVModel):
    pass


class ArmV8RSysVSigwait(Sigwait, ArmV8RSysVModel):
    pass


class ArmV8RSysVSigwaitinfo(Sigwaitinfo, ArmV8RSysVModel):
    pass


__all__ = [
    "ArmV8RSysVBsdSignal",
    "ArmV8RSysVKill",
    "ArmV8RSysVKillpg",
    "ArmV8RSysVPthreadKill",
    "ArmV8RSysVPthreadSigmask",
    "ArmV8RSysVSigaction",
    "ArmV8RSysVSigaddset",
    "ArmV8RSysVSigaltstack",
    "ArmV8RSysVSigdelset",
    "ArmV8RSysVSigemptyset",
    "ArmV8RSysVSigfillset",
    "ArmV8RSysVSighold",
    "ArmV8RSysVSigignore",
    "ArmV8RSysVSiginterrupt",
    "ArmV8RSysVSigismember",
    "ArmV8RSysVSigpause",
    "ArmV8RSysVSigpending",
    "ArmV8RSysVSigprocmask",
    "ArmV8RSysVSigqueue",
    "ArmV8RSysVSigrelse",
    "ArmV8RSysVSigset",
    "ArmV8RSysVSigsuspend",
    "ArmV8RSysVSigtimedwait",
    "ArmV8RSysVSigwait",
    "ArmV8RSysVSigwaitinfo",
]
