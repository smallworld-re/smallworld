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
from ..systemv import ArmV6KSysVModel


class ArmV6KSysVBsdSignal(BsdSignal, ArmV6KSysVModel):
    pass


class ArmV6KSysVKill(Kill, ArmV6KSysVModel):
    pass


class ArmV6KSysVKillpg(Killpg, ArmV6KSysVModel):
    pass


class ArmV6KSysVPthreadKill(PthreadKill, ArmV6KSysVModel):
    pass


class ArmV6KSysVPthreadSigmask(PthreadSigmask, ArmV6KSysVModel):
    pass


class ArmV6KSysVSigaction(Sigaction, ArmV6KSysVModel):
    pass


class ArmV6KSysVSigaddset(Sigaddset, ArmV6KSysVModel):
    pass


class ArmV6KSysVSigaltstack(Sigaltstack, ArmV6KSysVModel):
    pass


class ArmV6KSysVSigdelset(Sigdelset, ArmV6KSysVModel):
    pass


class ArmV6KSysVSigemptyset(Sigemptyset, ArmV6KSysVModel):
    pass


class ArmV6KSysVSigfillset(Sigfillset, ArmV6KSysVModel):
    pass


class ArmV6KSysVSighold(Sighold, ArmV6KSysVModel):
    pass


class ArmV6KSysVSigignore(Sigignore, ArmV6KSysVModel):
    pass


class ArmV6KSysVSiginterrupt(Siginterrupt, ArmV6KSysVModel):
    pass


class ArmV6KSysVSigismember(Sigismember, ArmV6KSysVModel):
    pass


class ArmV6KSysVSigpause(Sigpause, ArmV6KSysVModel):
    pass


class ArmV6KSysVSigpending(Sigpending, ArmV6KSysVModel):
    pass


class ArmV6KSysVSigprocmask(Sigprocmask, ArmV6KSysVModel):
    pass


class ArmV6KSysVSigqueue(Sigqueue, ArmV6KSysVModel):
    pass


class ArmV6KSysVSigrelse(Sigrelse, ArmV6KSysVModel):
    pass


class ArmV6KSysVSigset(Sigset, ArmV6KSysVModel):
    pass


class ArmV6KSysVSigsuspend(Sigsuspend, ArmV6KSysVModel):
    pass


class ArmV6KSysVSigtimedwait(Sigtimedwait, ArmV6KSysVModel):
    pass


class ArmV6KSysVSigwait(Sigwait, ArmV6KSysVModel):
    pass


class ArmV6KSysVSigwaitinfo(Sigwaitinfo, ArmV6KSysVModel):
    pass


__all__ = [
    "ArmV6KSysVBsdSignal",
    "ArmV6KSysVKill",
    "ArmV6KSysVKillpg",
    "ArmV6KSysVPthreadKill",
    "ArmV6KSysVPthreadSigmask",
    "ArmV6KSysVSigaction",
    "ArmV6KSysVSigaddset",
    "ArmV6KSysVSigaltstack",
    "ArmV6KSysVSigdelset",
    "ArmV6KSysVSigemptyset",
    "ArmV6KSysVSigfillset",
    "ArmV6KSysVSighold",
    "ArmV6KSysVSigignore",
    "ArmV6KSysVSiginterrupt",
    "ArmV6KSysVSigismember",
    "ArmV6KSysVSigpause",
    "ArmV6KSysVSigpending",
    "ArmV6KSysVSigprocmask",
    "ArmV6KSysVSigqueue",
    "ArmV6KSysVSigrelse",
    "ArmV6KSysVSigset",
    "ArmV6KSysVSigsuspend",
    "ArmV6KSysVSigtimedwait",
    "ArmV6KSysVSigwait",
    "ArmV6KSysVSigwaitinfo",
]
