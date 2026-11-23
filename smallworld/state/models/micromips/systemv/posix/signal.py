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
from ..systemv import MicroMIPSSysVModel


class MicroMIPSSysVBsdSignal(BsdSignal, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVKill(Kill, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVKillpg(Killpg, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVPthreadKill(PthreadKill, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVPthreadSigmask(PthreadSigmask, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSigaction(Sigaction, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSigaddset(Sigaddset, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSigaltstack(Sigaltstack, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSigdelset(Sigdelset, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSigemptyset(Sigemptyset, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSigfillset(Sigfillset, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSighold(Sighold, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSigignore(Sigignore, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSiginterrupt(Siginterrupt, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSigismember(Sigismember, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSigpause(Sigpause, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSigpending(Sigpending, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSigprocmask(Sigprocmask, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSigqueue(Sigqueue, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSigrelse(Sigrelse, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSigset(Sigset, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSigsuspend(Sigsuspend, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSigtimedwait(Sigtimedwait, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSigwait(Sigwait, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSigwaitinfo(Sigwaitinfo, MicroMIPSSysVModel):
    pass


__all__ = [
    "MicroMIPSSysVBsdSignal",
    "MicroMIPSSysVKill",
    "MicroMIPSSysVKillpg",
    "MicroMIPSSysVPthreadKill",
    "MicroMIPSSysVPthreadSigmask",
    "MicroMIPSSysVSigaction",
    "MicroMIPSSysVSigaddset",
    "MicroMIPSSysVSigaltstack",
    "MicroMIPSSysVSigdelset",
    "MicroMIPSSysVSigemptyset",
    "MicroMIPSSysVSigfillset",
    "MicroMIPSSysVSighold",
    "MicroMIPSSysVSigignore",
    "MicroMIPSSysVSiginterrupt",
    "MicroMIPSSysVSigismember",
    "MicroMIPSSysVSigpause",
    "MicroMIPSSysVSigpending",
    "MicroMIPSSysVSigprocmask",
    "MicroMIPSSysVSigqueue",
    "MicroMIPSSysVSigrelse",
    "MicroMIPSSysVSigset",
    "MicroMIPSSysVSigsuspend",
    "MicroMIPSSysVSigtimedwait",
    "MicroMIPSSysVSigwait",
    "MicroMIPSSysVSigwaitinfo",
]
