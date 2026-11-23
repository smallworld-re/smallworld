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
from ..systemv import AArch64V85ABESysVModel


class AArch64V85ABESysVBsdSignal(BsdSignal, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVKill(Kill, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVKillpg(Killpg, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVPthreadKill(PthreadKill, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVPthreadSigmask(PthreadSigmask, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSigaction(Sigaction, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSigaddset(Sigaddset, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSigaltstack(Sigaltstack, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSigdelset(Sigdelset, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSigemptyset(Sigemptyset, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSigfillset(Sigfillset, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSighold(Sighold, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSigignore(Sigignore, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSiginterrupt(Siginterrupt, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSigismember(Sigismember, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSigpause(Sigpause, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSigpending(Sigpending, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSigprocmask(Sigprocmask, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSigqueue(Sigqueue, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSigrelse(Sigrelse, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSigset(Sigset, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSigsuspend(Sigsuspend, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSigtimedwait(Sigtimedwait, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSigwait(Sigwait, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSigwaitinfo(Sigwaitinfo, AArch64V85ABESysVModel):
    pass


__all__ = [
    "AArch64V85ABESysVBsdSignal",
    "AArch64V85ABESysVKill",
    "AArch64V85ABESysVKillpg",
    "AArch64V85ABESysVPthreadKill",
    "AArch64V85ABESysVPthreadSigmask",
    "AArch64V85ABESysVSigaction",
    "AArch64V85ABESysVSigaddset",
    "AArch64V85ABESysVSigaltstack",
    "AArch64V85ABESysVSigdelset",
    "AArch64V85ABESysVSigemptyset",
    "AArch64V85ABESysVSigfillset",
    "AArch64V85ABESysVSighold",
    "AArch64V85ABESysVSigignore",
    "AArch64V85ABESysVSiginterrupt",
    "AArch64V85ABESysVSigismember",
    "AArch64V85ABESysVSigpause",
    "AArch64V85ABESysVSigpending",
    "AArch64V85ABESysVSigprocmask",
    "AArch64V85ABESysVSigqueue",
    "AArch64V85ABESysVSigrelse",
    "AArch64V85ABESysVSigset",
    "AArch64V85ABESysVSigsuspend",
    "AArch64V85ABESysVSigtimedwait",
    "AArch64V85ABESysVSigwait",
    "AArch64V85ABESysVSigwaitinfo",
]
