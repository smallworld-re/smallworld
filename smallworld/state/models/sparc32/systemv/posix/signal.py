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
from ..systemv import SPARC32SysVModel


class SPARC32SysVBsdSignal(BsdSignal, SPARC32SysVModel):
    pass


class SPARC32SysVKill(Kill, SPARC32SysVModel):
    pass


class SPARC32SysVKillpg(Killpg, SPARC32SysVModel):
    pass


class SPARC32SysVPthreadKill(PthreadKill, SPARC32SysVModel):
    pass


class SPARC32SysVPthreadSigmask(PthreadSigmask, SPARC32SysVModel):
    pass


class SPARC32SysVSigaction(Sigaction, SPARC32SysVModel):
    pass


class SPARC32SysVSigaddset(Sigaddset, SPARC32SysVModel):
    pass


class SPARC32SysVSigaltstack(Sigaltstack, SPARC32SysVModel):
    pass


class SPARC32SysVSigdelset(Sigdelset, SPARC32SysVModel):
    pass


class SPARC32SysVSigemptyset(Sigemptyset, SPARC32SysVModel):
    pass


class SPARC32SysVSigfillset(Sigfillset, SPARC32SysVModel):
    pass


class SPARC32SysVSighold(Sighold, SPARC32SysVModel):
    pass


class SPARC32SysVSigignore(Sigignore, SPARC32SysVModel):
    pass


class SPARC32SysVSiginterrupt(Siginterrupt, SPARC32SysVModel):
    pass


class SPARC32SysVSigismember(Sigismember, SPARC32SysVModel):
    pass


class SPARC32SysVSigpause(Sigpause, SPARC32SysVModel):
    pass


class SPARC32SysVSigpending(Sigpending, SPARC32SysVModel):
    pass


class SPARC32SysVSigprocmask(Sigprocmask, SPARC32SysVModel):
    pass


class SPARC32SysVSigqueue(Sigqueue, SPARC32SysVModel):
    pass


class SPARC32SysVSigrelse(Sigrelse, SPARC32SysVModel):
    pass


class SPARC32SysVSigset(Sigset, SPARC32SysVModel):
    pass


class SPARC32SysVSigsuspend(Sigsuspend, SPARC32SysVModel):
    pass


class SPARC32SysVSigtimedwait(Sigtimedwait, SPARC32SysVModel):
    pass


class SPARC32SysVSigwait(Sigwait, SPARC32SysVModel):
    pass


class SPARC32SysVSigwaitinfo(Sigwaitinfo, SPARC32SysVModel):
    pass


__all__ = [
    "SPARC32SysVBsdSignal",
    "SPARC32SysVKill",
    "SPARC32SysVKillpg",
    "SPARC32SysVPthreadKill",
    "SPARC32SysVPthreadSigmask",
    "SPARC32SysVSigaction",
    "SPARC32SysVSigaddset",
    "SPARC32SysVSigaltstack",
    "SPARC32SysVSigdelset",
    "SPARC32SysVSigemptyset",
    "SPARC32SysVSigfillset",
    "SPARC32SysVSighold",
    "SPARC32SysVSigignore",
    "SPARC32SysVSiginterrupt",
    "SPARC32SysVSigismember",
    "SPARC32SysVSigpause",
    "SPARC32SysVSigpending",
    "SPARC32SysVSigprocmask",
    "SPARC32SysVSigqueue",
    "SPARC32SysVSigrelse",
    "SPARC32SysVSigset",
    "SPARC32SysVSigsuspend",
    "SPARC32SysVSigtimedwait",
    "SPARC32SysVSigwait",
    "SPARC32SysVSigwaitinfo",
]
