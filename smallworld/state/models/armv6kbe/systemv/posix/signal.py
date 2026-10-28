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
from ..systemv import ArmV6KBESysVModel


class ArmV6KBESysVBsdSignal(BsdSignal, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVKill(Kill, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVKillpg(Killpg, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVPthreadKill(PthreadKill, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVPthreadSigmask(PthreadSigmask, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSigaction(Sigaction, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSigaddset(Sigaddset, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSigaltstack(Sigaltstack, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSigdelset(Sigdelset, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSigemptyset(Sigemptyset, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSigfillset(Sigfillset, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSighold(Sighold, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSigignore(Sigignore, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSiginterrupt(Siginterrupt, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSigismember(Sigismember, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSigpause(Sigpause, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSigpending(Sigpending, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSigprocmask(Sigprocmask, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSigqueue(Sigqueue, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSigrelse(Sigrelse, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSigset(Sigset, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSigsuspend(Sigsuspend, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSigtimedwait(Sigtimedwait, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSigwait(Sigwait, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSigwaitinfo(Sigwaitinfo, ArmV6KBESysVModel):
    pass


__all__ = [
    "ArmV6KBESysVBsdSignal",
    "ArmV6KBESysVKill",
    "ArmV6KBESysVKillpg",
    "ArmV6KBESysVPthreadKill",
    "ArmV6KBESysVPthreadSigmask",
    "ArmV6KBESysVSigaction",
    "ArmV6KBESysVSigaddset",
    "ArmV6KBESysVSigaltstack",
    "ArmV6KBESysVSigdelset",
    "ArmV6KBESysVSigemptyset",
    "ArmV6KBESysVSigfillset",
    "ArmV6KBESysVSighold",
    "ArmV6KBESysVSigignore",
    "ArmV6KBESysVSiginterrupt",
    "ArmV6KBESysVSigismember",
    "ArmV6KBESysVSigpause",
    "ArmV6KBESysVSigpending",
    "ArmV6KBESysVSigprocmask",
    "ArmV6KBESysVSigqueue",
    "ArmV6KBESysVSigrelse",
    "ArmV6KBESysVSigset",
    "ArmV6KBESysVSigsuspend",
    "ArmV6KBESysVSigtimedwait",
    "ArmV6KBESysVSigwait",
    "ArmV6KBESysVSigwaitinfo",
]
