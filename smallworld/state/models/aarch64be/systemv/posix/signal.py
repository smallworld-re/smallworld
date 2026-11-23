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
from ..systemv import AArch64BESysVModel


class AArch64BESysVBsdSignal(BsdSignal, AArch64BESysVModel):
    pass


class AArch64BESysVKill(Kill, AArch64BESysVModel):
    pass


class AArch64BESysVKillpg(Killpg, AArch64BESysVModel):
    pass


class AArch64BESysVPthreadKill(PthreadKill, AArch64BESysVModel):
    pass


class AArch64BESysVPthreadSigmask(PthreadSigmask, AArch64BESysVModel):
    pass


class AArch64BESysVSigaction(Sigaction, AArch64BESysVModel):
    pass


class AArch64BESysVSigaddset(Sigaddset, AArch64BESysVModel):
    pass


class AArch64BESysVSigaltstack(Sigaltstack, AArch64BESysVModel):
    pass


class AArch64BESysVSigdelset(Sigdelset, AArch64BESysVModel):
    pass


class AArch64BESysVSigemptyset(Sigemptyset, AArch64BESysVModel):
    pass


class AArch64BESysVSigfillset(Sigfillset, AArch64BESysVModel):
    pass


class AArch64BESysVSighold(Sighold, AArch64BESysVModel):
    pass


class AArch64BESysVSigignore(Sigignore, AArch64BESysVModel):
    pass


class AArch64BESysVSiginterrupt(Siginterrupt, AArch64BESysVModel):
    pass


class AArch64BESysVSigismember(Sigismember, AArch64BESysVModel):
    pass


class AArch64BESysVSigpause(Sigpause, AArch64BESysVModel):
    pass


class AArch64BESysVSigpending(Sigpending, AArch64BESysVModel):
    pass


class AArch64BESysVSigprocmask(Sigprocmask, AArch64BESysVModel):
    pass


class AArch64BESysVSigqueue(Sigqueue, AArch64BESysVModel):
    pass


class AArch64BESysVSigrelse(Sigrelse, AArch64BESysVModel):
    pass


class AArch64BESysVSigset(Sigset, AArch64BESysVModel):
    pass


class AArch64BESysVSigsuspend(Sigsuspend, AArch64BESysVModel):
    pass


class AArch64BESysVSigtimedwait(Sigtimedwait, AArch64BESysVModel):
    pass


class AArch64BESysVSigwait(Sigwait, AArch64BESysVModel):
    pass


class AArch64BESysVSigwaitinfo(Sigwaitinfo, AArch64BESysVModel):
    pass


__all__ = [
    "AArch64BESysVBsdSignal",
    "AArch64BESysVKill",
    "AArch64BESysVKillpg",
    "AArch64BESysVPthreadKill",
    "AArch64BESysVPthreadSigmask",
    "AArch64BESysVSigaction",
    "AArch64BESysVSigaddset",
    "AArch64BESysVSigaltstack",
    "AArch64BESysVSigdelset",
    "AArch64BESysVSigemptyset",
    "AArch64BESysVSigfillset",
    "AArch64BESysVSighold",
    "AArch64BESysVSigignore",
    "AArch64BESysVSiginterrupt",
    "AArch64BESysVSigismember",
    "AArch64BESysVSigpause",
    "AArch64BESysVSigpending",
    "AArch64BESysVSigprocmask",
    "AArch64BESysVSigqueue",
    "AArch64BESysVSigrelse",
    "AArch64BESysVSigset",
    "AArch64BESysVSigsuspend",
    "AArch64BESysVSigtimedwait",
    "AArch64BESysVSigwait",
    "AArch64BESysVSigwaitinfo",
]
