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
from ..systemv import ArmV7RSysVModel


class ArmV7RSysVBsdSignal(BsdSignal, ArmV7RSysVModel):
    pass


class ArmV7RSysVKill(Kill, ArmV7RSysVModel):
    pass


class ArmV7RSysVKillpg(Killpg, ArmV7RSysVModel):
    pass


class ArmV7RSysVPthreadKill(PthreadKill, ArmV7RSysVModel):
    pass


class ArmV7RSysVPthreadSigmask(PthreadSigmask, ArmV7RSysVModel):
    pass


class ArmV7RSysVSigaction(Sigaction, ArmV7RSysVModel):
    pass


class ArmV7RSysVSigaddset(Sigaddset, ArmV7RSysVModel):
    pass


class ArmV7RSysVSigaltstack(Sigaltstack, ArmV7RSysVModel):
    pass


class ArmV7RSysVSigdelset(Sigdelset, ArmV7RSysVModel):
    pass


class ArmV7RSysVSigemptyset(Sigemptyset, ArmV7RSysVModel):
    pass


class ArmV7RSysVSigfillset(Sigfillset, ArmV7RSysVModel):
    pass


class ArmV7RSysVSighold(Sighold, ArmV7RSysVModel):
    pass


class ArmV7RSysVSigignore(Sigignore, ArmV7RSysVModel):
    pass


class ArmV7RSysVSiginterrupt(Siginterrupt, ArmV7RSysVModel):
    pass


class ArmV7RSysVSigismember(Sigismember, ArmV7RSysVModel):
    pass


class ArmV7RSysVSigpause(Sigpause, ArmV7RSysVModel):
    pass


class ArmV7RSysVSigpending(Sigpending, ArmV7RSysVModel):
    pass


class ArmV7RSysVSigprocmask(Sigprocmask, ArmV7RSysVModel):
    pass


class ArmV7RSysVSigqueue(Sigqueue, ArmV7RSysVModel):
    pass


class ArmV7RSysVSigrelse(Sigrelse, ArmV7RSysVModel):
    pass


class ArmV7RSysVSigset(Sigset, ArmV7RSysVModel):
    pass


class ArmV7RSysVSigsuspend(Sigsuspend, ArmV7RSysVModel):
    pass


class ArmV7RSysVSigtimedwait(Sigtimedwait, ArmV7RSysVModel):
    pass


class ArmV7RSysVSigwait(Sigwait, ArmV7RSysVModel):
    pass


class ArmV7RSysVSigwaitinfo(Sigwaitinfo, ArmV7RSysVModel):
    pass


__all__ = [
    "ArmV7RSysVBsdSignal",
    "ArmV7RSysVKill",
    "ArmV7RSysVKillpg",
    "ArmV7RSysVPthreadKill",
    "ArmV7RSysVPthreadSigmask",
    "ArmV7RSysVSigaction",
    "ArmV7RSysVSigaddset",
    "ArmV7RSysVSigaltstack",
    "ArmV7RSysVSigdelset",
    "ArmV7RSysVSigemptyset",
    "ArmV7RSysVSigfillset",
    "ArmV7RSysVSighold",
    "ArmV7RSysVSigignore",
    "ArmV7RSysVSiginterrupt",
    "ArmV7RSysVSigismember",
    "ArmV7RSysVSigpause",
    "ArmV7RSysVSigpending",
    "ArmV7RSysVSigprocmask",
    "ArmV7RSysVSigqueue",
    "ArmV7RSysVSigrelse",
    "ArmV7RSysVSigset",
    "ArmV7RSysVSigsuspend",
    "ArmV7RSysVSigtimedwait",
    "ArmV7RSysVSigwait",
    "ArmV7RSysVSigwaitinfo",
]
