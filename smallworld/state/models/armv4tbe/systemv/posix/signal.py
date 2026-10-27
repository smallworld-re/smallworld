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
from ..systemv import ArmV4TBESysVModel


class ArmV4TBESysVBsdSignal(BsdSignal, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVKill(Kill, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVKillpg(Killpg, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVPthreadKill(PthreadKill, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVPthreadSigmask(PthreadSigmask, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSigaction(Sigaction, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSigaddset(Sigaddset, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSigaltstack(Sigaltstack, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSigdelset(Sigdelset, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSigemptyset(Sigemptyset, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSigfillset(Sigfillset, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSighold(Sighold, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSigignore(Sigignore, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSiginterrupt(Siginterrupt, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSigismember(Sigismember, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSigpause(Sigpause, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSigpending(Sigpending, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSigprocmask(Sigprocmask, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSigqueue(Sigqueue, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSigrelse(Sigrelse, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSigset(Sigset, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSigsuspend(Sigsuspend, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSigtimedwait(Sigtimedwait, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSigwait(Sigwait, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSigwaitinfo(Sigwaitinfo, ArmV4TBESysVModel):
    pass


__all__ = [
    "ArmV4TBESysVBsdSignal",
    "ArmV4TBESysVKill",
    "ArmV4TBESysVKillpg",
    "ArmV4TBESysVPthreadKill",
    "ArmV4TBESysVPthreadSigmask",
    "ArmV4TBESysVSigaction",
    "ArmV4TBESysVSigaddset",
    "ArmV4TBESysVSigaltstack",
    "ArmV4TBESysVSigdelset",
    "ArmV4TBESysVSigemptyset",
    "ArmV4TBESysVSigfillset",
    "ArmV4TBESysVSighold",
    "ArmV4TBESysVSigignore",
    "ArmV4TBESysVSiginterrupt",
    "ArmV4TBESysVSigismember",
    "ArmV4TBESysVSigpause",
    "ArmV4TBESysVSigpending",
    "ArmV4TBESysVSigprocmask",
    "ArmV4TBESysVSigqueue",
    "ArmV4TBESysVSigrelse",
    "ArmV4TBESysVSigset",
    "ArmV4TBESysVSigsuspend",
    "ArmV4TBESysVSigtimedwait",
    "ArmV4TBESysVSigwait",
    "ArmV4TBESysVSigwaitinfo",
]
