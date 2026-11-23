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
from ..systemv import ArmV7ABESysVModel


class ArmV7ABESysVBsdSignal(BsdSignal, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVKill(Kill, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVKillpg(Killpg, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVPthreadKill(PthreadKill, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVPthreadSigmask(PthreadSigmask, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSigaction(Sigaction, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSigaddset(Sigaddset, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSigaltstack(Sigaltstack, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSigdelset(Sigdelset, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSigemptyset(Sigemptyset, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSigfillset(Sigfillset, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSighold(Sighold, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSigignore(Sigignore, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSiginterrupt(Siginterrupt, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSigismember(Sigismember, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSigpause(Sigpause, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSigpending(Sigpending, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSigprocmask(Sigprocmask, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSigqueue(Sigqueue, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSigrelse(Sigrelse, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSigset(Sigset, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSigsuspend(Sigsuspend, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSigtimedwait(Sigtimedwait, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSigwait(Sigwait, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSigwaitinfo(Sigwaitinfo, ArmV7ABESysVModel):
    pass


__all__ = [
    "ArmV7ABESysVBsdSignal",
    "ArmV7ABESysVKill",
    "ArmV7ABESysVKillpg",
    "ArmV7ABESysVPthreadKill",
    "ArmV7ABESysVPthreadSigmask",
    "ArmV7ABESysVSigaction",
    "ArmV7ABESysVSigaddset",
    "ArmV7ABESysVSigaltstack",
    "ArmV7ABESysVSigdelset",
    "ArmV7ABESysVSigemptyset",
    "ArmV7ABESysVSigfillset",
    "ArmV7ABESysVSighold",
    "ArmV7ABESysVSigignore",
    "ArmV7ABESysVSiginterrupt",
    "ArmV7ABESysVSigismember",
    "ArmV7ABESysVSigpause",
    "ArmV7ABESysVSigpending",
    "ArmV7ABESysVSigprocmask",
    "ArmV7ABESysVSigqueue",
    "ArmV7ABESysVSigrelse",
    "ArmV7ABESysVSigset",
    "ArmV7ABESysVSigsuspend",
    "ArmV7ABESysVSigtimedwait",
    "ArmV7ABESysVSigwait",
    "ArmV7ABESysVSigwaitinfo",
]
