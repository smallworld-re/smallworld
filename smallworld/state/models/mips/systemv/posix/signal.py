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
from ..systemv import MIPSSysVModel


class MIPSSysVBsdSignal(BsdSignal, MIPSSysVModel):
    pass


class MIPSSysVKill(Kill, MIPSSysVModel):
    pass


class MIPSSysVKillpg(Killpg, MIPSSysVModel):
    pass


class MIPSSysVPthreadKill(PthreadKill, MIPSSysVModel):
    pass


class MIPSSysVPthreadSigmask(PthreadSigmask, MIPSSysVModel):
    pass


class MIPSSysVSigaction(Sigaction, MIPSSysVModel):
    pass


class MIPSSysVSigaddset(Sigaddset, MIPSSysVModel):
    pass


class MIPSSysVSigaltstack(Sigaltstack, MIPSSysVModel):
    pass


class MIPSSysVSigdelset(Sigdelset, MIPSSysVModel):
    pass


class MIPSSysVSigemptyset(Sigemptyset, MIPSSysVModel):
    pass


class MIPSSysVSigfillset(Sigfillset, MIPSSysVModel):
    pass


class MIPSSysVSighold(Sighold, MIPSSysVModel):
    pass


class MIPSSysVSigignore(Sigignore, MIPSSysVModel):
    pass


class MIPSSysVSiginterrupt(Siginterrupt, MIPSSysVModel):
    pass


class MIPSSysVSigismember(Sigismember, MIPSSysVModel):
    pass


class MIPSSysVSigpause(Sigpause, MIPSSysVModel):
    pass


class MIPSSysVSigpending(Sigpending, MIPSSysVModel):
    pass


class MIPSSysVSigprocmask(Sigprocmask, MIPSSysVModel):
    pass


class MIPSSysVSigqueue(Sigqueue, MIPSSysVModel):
    pass


class MIPSSysVSigrelse(Sigrelse, MIPSSysVModel):
    pass


class MIPSSysVSigset(Sigset, MIPSSysVModel):
    pass


class MIPSSysVSigsuspend(Sigsuspend, MIPSSysVModel):
    pass


class MIPSSysVSigtimedwait(Sigtimedwait, MIPSSysVModel):
    pass


class MIPSSysVSigwait(Sigwait, MIPSSysVModel):
    pass


class MIPSSysVSigwaitinfo(Sigwaitinfo, MIPSSysVModel):
    pass


__all__ = [
    "MIPSSysVBsdSignal",
    "MIPSSysVKill",
    "MIPSSysVKillpg",
    "MIPSSysVPthreadKill",
    "MIPSSysVPthreadSigmask",
    "MIPSSysVSigaction",
    "MIPSSysVSigaddset",
    "MIPSSysVSigaltstack",
    "MIPSSysVSigdelset",
    "MIPSSysVSigemptyset",
    "MIPSSysVSigfillset",
    "MIPSSysVSighold",
    "MIPSSysVSigignore",
    "MIPSSysVSiginterrupt",
    "MIPSSysVSigismember",
    "MIPSSysVSigpause",
    "MIPSSysVSigpending",
    "MIPSSysVSigprocmask",
    "MIPSSysVSigqueue",
    "MIPSSysVSigrelse",
    "MIPSSysVSigset",
    "MIPSSysVSigsuspend",
    "MIPSSysVSigtimedwait",
    "MIPSSysVSigwait",
    "MIPSSysVSigwaitinfo",
]
