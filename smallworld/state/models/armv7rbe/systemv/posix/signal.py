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
from ..systemv import ArmV7RBESysVModel


class ArmV7RBESysVBsdSignal(BsdSignal, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVKill(Kill, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVKillpg(Killpg, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVPthreadKill(PthreadKill, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVPthreadSigmask(PthreadSigmask, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSigaction(Sigaction, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSigaddset(Sigaddset, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSigaltstack(Sigaltstack, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSigdelset(Sigdelset, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSigemptyset(Sigemptyset, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSigfillset(Sigfillset, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSighold(Sighold, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSigignore(Sigignore, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSiginterrupt(Siginterrupt, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSigismember(Sigismember, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSigpause(Sigpause, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSigpending(Sigpending, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSigprocmask(Sigprocmask, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSigqueue(Sigqueue, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSigrelse(Sigrelse, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSigset(Sigset, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSigsuspend(Sigsuspend, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSigtimedwait(Sigtimedwait, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSigwait(Sigwait, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSigwaitinfo(Sigwaitinfo, ArmV7RBESysVModel):
    pass


__all__ = [
    "ArmV7RBESysVBsdSignal",
    "ArmV7RBESysVKill",
    "ArmV7RBESysVKillpg",
    "ArmV7RBESysVPthreadKill",
    "ArmV7RBESysVPthreadSigmask",
    "ArmV7RBESysVSigaction",
    "ArmV7RBESysVSigaddset",
    "ArmV7RBESysVSigaltstack",
    "ArmV7RBESysVSigdelset",
    "ArmV7RBESysVSigemptyset",
    "ArmV7RBESysVSigfillset",
    "ArmV7RBESysVSighold",
    "ArmV7RBESysVSigignore",
    "ArmV7RBESysVSiginterrupt",
    "ArmV7RBESysVSigismember",
    "ArmV7RBESysVSigpause",
    "ArmV7RBESysVSigpending",
    "ArmV7RBESysVSigprocmask",
    "ArmV7RBESysVSigqueue",
    "ArmV7RBESysVSigrelse",
    "ArmV7RBESysVSigset",
    "ArmV7RBESysVSigsuspend",
    "ArmV7RBESysVSigtimedwait",
    "ArmV7RBESysVSigwait",
    "ArmV7RBESysVSigwaitinfo",
]
