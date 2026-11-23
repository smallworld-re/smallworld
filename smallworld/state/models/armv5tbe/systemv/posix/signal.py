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
from ..systemv import ArmV5TBESysVModel


class ArmV5TBESysVBsdSignal(BsdSignal, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVKill(Kill, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVKillpg(Killpg, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVPthreadKill(PthreadKill, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVPthreadSigmask(PthreadSigmask, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSigaction(Sigaction, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSigaddset(Sigaddset, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSigaltstack(Sigaltstack, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSigdelset(Sigdelset, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSigemptyset(Sigemptyset, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSigfillset(Sigfillset, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSighold(Sighold, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSigignore(Sigignore, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSiginterrupt(Siginterrupt, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSigismember(Sigismember, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSigpause(Sigpause, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSigpending(Sigpending, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSigprocmask(Sigprocmask, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSigqueue(Sigqueue, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSigrelse(Sigrelse, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSigset(Sigset, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSigsuspend(Sigsuspend, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSigtimedwait(Sigtimedwait, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSigwait(Sigwait, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSigwaitinfo(Sigwaitinfo, ArmV5TBESysVModel):
    pass


__all__ = [
    "ArmV5TBESysVBsdSignal",
    "ArmV5TBESysVKill",
    "ArmV5TBESysVKillpg",
    "ArmV5TBESysVPthreadKill",
    "ArmV5TBESysVPthreadSigmask",
    "ArmV5TBESysVSigaction",
    "ArmV5TBESysVSigaddset",
    "ArmV5TBESysVSigaltstack",
    "ArmV5TBESysVSigdelset",
    "ArmV5TBESysVSigemptyset",
    "ArmV5TBESysVSigfillset",
    "ArmV5TBESysVSighold",
    "ArmV5TBESysVSigignore",
    "ArmV5TBESysVSiginterrupt",
    "ArmV5TBESysVSigismember",
    "ArmV5TBESysVSigpause",
    "ArmV5TBESysVSigpending",
    "ArmV5TBESysVSigprocmask",
    "ArmV5TBESysVSigqueue",
    "ArmV5TBESysVSigrelse",
    "ArmV5TBESysVSigset",
    "ArmV5TBESysVSigsuspend",
    "ArmV5TBESysVSigtimedwait",
    "ArmV5TBESysVSigwait",
    "ArmV5TBESysVSigwaitinfo",
]
