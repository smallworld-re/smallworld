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
from ..systemv import ArmV7MSysVModel


class ArmV7MSysVBsdSignal(BsdSignal, ArmV7MSysVModel):
    pass


class ArmV7MSysVKill(Kill, ArmV7MSysVModel):
    pass


class ArmV7MSysVKillpg(Killpg, ArmV7MSysVModel):
    pass


class ArmV7MSysVPthreadKill(PthreadKill, ArmV7MSysVModel):
    pass


class ArmV7MSysVPthreadSigmask(PthreadSigmask, ArmV7MSysVModel):
    pass


class ArmV7MSysVSigaction(Sigaction, ArmV7MSysVModel):
    pass


class ArmV7MSysVSigaddset(Sigaddset, ArmV7MSysVModel):
    pass


class ArmV7MSysVSigaltstack(Sigaltstack, ArmV7MSysVModel):
    pass


class ArmV7MSysVSigdelset(Sigdelset, ArmV7MSysVModel):
    pass


class ArmV7MSysVSigemptyset(Sigemptyset, ArmV7MSysVModel):
    pass


class ArmV7MSysVSigfillset(Sigfillset, ArmV7MSysVModel):
    pass


class ArmV7MSysVSighold(Sighold, ArmV7MSysVModel):
    pass


class ArmV7MSysVSigignore(Sigignore, ArmV7MSysVModel):
    pass


class ArmV7MSysVSiginterrupt(Siginterrupt, ArmV7MSysVModel):
    pass


class ArmV7MSysVSigismember(Sigismember, ArmV7MSysVModel):
    pass


class ArmV7MSysVSigpause(Sigpause, ArmV7MSysVModel):
    pass


class ArmV7MSysVSigpending(Sigpending, ArmV7MSysVModel):
    pass


class ArmV7MSysVSigprocmask(Sigprocmask, ArmV7MSysVModel):
    pass


class ArmV7MSysVSigqueue(Sigqueue, ArmV7MSysVModel):
    pass


class ArmV7MSysVSigrelse(Sigrelse, ArmV7MSysVModel):
    pass


class ArmV7MSysVSigset(Sigset, ArmV7MSysVModel):
    pass


class ArmV7MSysVSigsuspend(Sigsuspend, ArmV7MSysVModel):
    pass


class ArmV7MSysVSigtimedwait(Sigtimedwait, ArmV7MSysVModel):
    pass


class ArmV7MSysVSigwait(Sigwait, ArmV7MSysVModel):
    pass


class ArmV7MSysVSigwaitinfo(Sigwaitinfo, ArmV7MSysVModel):
    pass


__all__ = [
    "ArmV7MSysVBsdSignal",
    "ArmV7MSysVKill",
    "ArmV7MSysVKillpg",
    "ArmV7MSysVPthreadKill",
    "ArmV7MSysVPthreadSigmask",
    "ArmV7MSysVSigaction",
    "ArmV7MSysVSigaddset",
    "ArmV7MSysVSigaltstack",
    "ArmV7MSysVSigdelset",
    "ArmV7MSysVSigemptyset",
    "ArmV7MSysVSigfillset",
    "ArmV7MSysVSighold",
    "ArmV7MSysVSigignore",
    "ArmV7MSysVSiginterrupt",
    "ArmV7MSysVSigismember",
    "ArmV7MSysVSigpause",
    "ArmV7MSysVSigpending",
    "ArmV7MSysVSigprocmask",
    "ArmV7MSysVSigqueue",
    "ArmV7MSysVSigrelse",
    "ArmV7MSysVSigset",
    "ArmV7MSysVSigsuspend",
    "ArmV7MSysVSigtimedwait",
    "ArmV7MSysVSigwait",
    "ArmV7MSysVSigwaitinfo",
]
