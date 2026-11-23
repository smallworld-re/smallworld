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
from ..systemv import ArmV4TSysVModel


class ArmV4TSysVBsdSignal(BsdSignal, ArmV4TSysVModel):
    pass


class ArmV4TSysVKill(Kill, ArmV4TSysVModel):
    pass


class ArmV4TSysVKillpg(Killpg, ArmV4TSysVModel):
    pass


class ArmV4TSysVPthreadKill(PthreadKill, ArmV4TSysVModel):
    pass


class ArmV4TSysVPthreadSigmask(PthreadSigmask, ArmV4TSysVModel):
    pass


class ArmV4TSysVSigaction(Sigaction, ArmV4TSysVModel):
    pass


class ArmV4TSysVSigaddset(Sigaddset, ArmV4TSysVModel):
    pass


class ArmV4TSysVSigaltstack(Sigaltstack, ArmV4TSysVModel):
    pass


class ArmV4TSysVSigdelset(Sigdelset, ArmV4TSysVModel):
    pass


class ArmV4TSysVSigemptyset(Sigemptyset, ArmV4TSysVModel):
    pass


class ArmV4TSysVSigfillset(Sigfillset, ArmV4TSysVModel):
    pass


class ArmV4TSysVSighold(Sighold, ArmV4TSysVModel):
    pass


class ArmV4TSysVSigignore(Sigignore, ArmV4TSysVModel):
    pass


class ArmV4TSysVSiginterrupt(Siginterrupt, ArmV4TSysVModel):
    pass


class ArmV4TSysVSigismember(Sigismember, ArmV4TSysVModel):
    pass


class ArmV4TSysVSigpause(Sigpause, ArmV4TSysVModel):
    pass


class ArmV4TSysVSigpending(Sigpending, ArmV4TSysVModel):
    pass


class ArmV4TSysVSigprocmask(Sigprocmask, ArmV4TSysVModel):
    pass


class ArmV4TSysVSigqueue(Sigqueue, ArmV4TSysVModel):
    pass


class ArmV4TSysVSigrelse(Sigrelse, ArmV4TSysVModel):
    pass


class ArmV4TSysVSigset(Sigset, ArmV4TSysVModel):
    pass


class ArmV4TSysVSigsuspend(Sigsuspend, ArmV4TSysVModel):
    pass


class ArmV4TSysVSigtimedwait(Sigtimedwait, ArmV4TSysVModel):
    pass


class ArmV4TSysVSigwait(Sigwait, ArmV4TSysVModel):
    pass


class ArmV4TSysVSigwaitinfo(Sigwaitinfo, ArmV4TSysVModel):
    pass


__all__ = [
    "ArmV4TSysVBsdSignal",
    "ArmV4TSysVKill",
    "ArmV4TSysVKillpg",
    "ArmV4TSysVPthreadKill",
    "ArmV4TSysVPthreadSigmask",
    "ArmV4TSysVSigaction",
    "ArmV4TSysVSigaddset",
    "ArmV4TSysVSigaltstack",
    "ArmV4TSysVSigdelset",
    "ArmV4TSysVSigemptyset",
    "ArmV4TSysVSigfillset",
    "ArmV4TSysVSighold",
    "ArmV4TSysVSigignore",
    "ArmV4TSysVSiginterrupt",
    "ArmV4TSysVSigismember",
    "ArmV4TSysVSigpause",
    "ArmV4TSysVSigpending",
    "ArmV4TSysVSigprocmask",
    "ArmV4TSysVSigqueue",
    "ArmV4TSysVSigrelse",
    "ArmV4TSysVSigset",
    "ArmV4TSysVSigsuspend",
    "ArmV4TSysVSigtimedwait",
    "ArmV4TSysVSigwait",
    "ArmV4TSysVSigwaitinfo",
]
