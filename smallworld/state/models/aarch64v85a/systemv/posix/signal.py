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
from ..systemv import AArch64V85ASysVModel


class AArch64V85ASysVBsdSignal(BsdSignal, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVKill(Kill, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVKillpg(Killpg, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVPthreadKill(PthreadKill, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVPthreadSigmask(PthreadSigmask, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSigaction(Sigaction, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSigaddset(Sigaddset, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSigaltstack(Sigaltstack, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSigdelset(Sigdelset, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSigemptyset(Sigemptyset, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSigfillset(Sigfillset, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSighold(Sighold, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSigignore(Sigignore, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSiginterrupt(Siginterrupt, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSigismember(Sigismember, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSigpause(Sigpause, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSigpending(Sigpending, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSigprocmask(Sigprocmask, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSigqueue(Sigqueue, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSigrelse(Sigrelse, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSigset(Sigset, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSigsuspend(Sigsuspend, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSigtimedwait(Sigtimedwait, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSigwait(Sigwait, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSigwaitinfo(Sigwaitinfo, AArch64V85ASysVModel):
    pass


__all__ = [
    "AArch64V85ASysVBsdSignal",
    "AArch64V85ASysVKill",
    "AArch64V85ASysVKillpg",
    "AArch64V85ASysVPthreadKill",
    "AArch64V85ASysVPthreadSigmask",
    "AArch64V85ASysVSigaction",
    "AArch64V85ASysVSigaddset",
    "AArch64V85ASysVSigaltstack",
    "AArch64V85ASysVSigdelset",
    "AArch64V85ASysVSigemptyset",
    "AArch64V85ASysVSigfillset",
    "AArch64V85ASysVSighold",
    "AArch64V85ASysVSigignore",
    "AArch64V85ASysVSiginterrupt",
    "AArch64V85ASysVSigismember",
    "AArch64V85ASysVSigpause",
    "AArch64V85ASysVSigpending",
    "AArch64V85ASysVSigprocmask",
    "AArch64V85ASysVSigqueue",
    "AArch64V85ASysVSigrelse",
    "AArch64V85ASysVSigset",
    "AArch64V85ASysVSigsuspend",
    "AArch64V85ASysVSigtimedwait",
    "AArch64V85ASysVSigwait",
    "AArch64V85ASysVSigwaitinfo",
]
