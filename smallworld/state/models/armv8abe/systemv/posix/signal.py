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
from ..systemv import ArmV8ABESysVModel


class ArmV8ABESysVBsdSignal(BsdSignal, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVKill(Kill, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVKillpg(Killpg, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVPthreadKill(PthreadKill, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVPthreadSigmask(PthreadSigmask, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSigaction(Sigaction, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSigaddset(Sigaddset, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSigaltstack(Sigaltstack, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSigdelset(Sigdelset, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSigemptyset(Sigemptyset, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSigfillset(Sigfillset, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSighold(Sighold, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSigignore(Sigignore, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSiginterrupt(Siginterrupt, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSigismember(Sigismember, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSigpause(Sigpause, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSigpending(Sigpending, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSigprocmask(Sigprocmask, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSigqueue(Sigqueue, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSigrelse(Sigrelse, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSigset(Sigset, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSigsuspend(Sigsuspend, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSigtimedwait(Sigtimedwait, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSigwait(Sigwait, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSigwaitinfo(Sigwaitinfo, ArmV8ABESysVModel):
    pass


__all__ = [
    "ArmV8ABESysVBsdSignal",
    "ArmV8ABESysVKill",
    "ArmV8ABESysVKillpg",
    "ArmV8ABESysVPthreadKill",
    "ArmV8ABESysVPthreadSigmask",
    "ArmV8ABESysVSigaction",
    "ArmV8ABESysVSigaddset",
    "ArmV8ABESysVSigaltstack",
    "ArmV8ABESysVSigdelset",
    "ArmV8ABESysVSigemptyset",
    "ArmV8ABESysVSigfillset",
    "ArmV8ABESysVSighold",
    "ArmV8ABESysVSigignore",
    "ArmV8ABESysVSiginterrupt",
    "ArmV8ABESysVSigismember",
    "ArmV8ABESysVSigpause",
    "ArmV8ABESysVSigpending",
    "ArmV8ABESysVSigprocmask",
    "ArmV8ABESysVSigqueue",
    "ArmV8ABESysVSigrelse",
    "ArmV8ABESysVSigset",
    "ArmV8ABESysVSigsuspend",
    "ArmV8ABESysVSigtimedwait",
    "ArmV8ABESysVSigwait",
    "ArmV8ABESysVSigwaitinfo",
]
