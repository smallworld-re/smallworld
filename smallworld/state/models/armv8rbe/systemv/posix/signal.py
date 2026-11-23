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
from ..systemv import ArmV8RBESysVModel


class ArmV8RBESysVBsdSignal(BsdSignal, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVKill(Kill, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVKillpg(Killpg, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVPthreadKill(PthreadKill, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVPthreadSigmask(PthreadSigmask, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSigaction(Sigaction, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSigaddset(Sigaddset, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSigaltstack(Sigaltstack, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSigdelset(Sigdelset, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSigemptyset(Sigemptyset, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSigfillset(Sigfillset, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSighold(Sighold, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSigignore(Sigignore, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSiginterrupt(Siginterrupt, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSigismember(Sigismember, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSigpause(Sigpause, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSigpending(Sigpending, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSigprocmask(Sigprocmask, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSigqueue(Sigqueue, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSigrelse(Sigrelse, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSigset(Sigset, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSigsuspend(Sigsuspend, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSigtimedwait(Sigtimedwait, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSigwait(Sigwait, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSigwaitinfo(Sigwaitinfo, ArmV8RBESysVModel):
    pass


__all__ = [
    "ArmV8RBESysVBsdSignal",
    "ArmV8RBESysVKill",
    "ArmV8RBESysVKillpg",
    "ArmV8RBESysVPthreadKill",
    "ArmV8RBESysVPthreadSigmask",
    "ArmV8RBESysVSigaction",
    "ArmV8RBESysVSigaddset",
    "ArmV8RBESysVSigaltstack",
    "ArmV8RBESysVSigdelset",
    "ArmV8RBESysVSigemptyset",
    "ArmV8RBESysVSigfillset",
    "ArmV8RBESysVSighold",
    "ArmV8RBESysVSigignore",
    "ArmV8RBESysVSiginterrupt",
    "ArmV8RBESysVSigismember",
    "ArmV8RBESysVSigpause",
    "ArmV8RBESysVSigpending",
    "ArmV8RBESysVSigprocmask",
    "ArmV8RBESysVSigqueue",
    "ArmV8RBESysVSigrelse",
    "ArmV8RBESysVSigset",
    "ArmV8RBESysVSigsuspend",
    "ArmV8RBESysVSigtimedwait",
    "ArmV8RBESysVSigwait",
    "ArmV8RBESysVSigwaitinfo",
]
