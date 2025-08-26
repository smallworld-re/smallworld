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
from ..systemv import AMD64SysVModel


class AMD64SysVBsdSignal(BsdSignal, AMD64SysVModel):
    pass


class AMD64SysVKill(Kill, AMD64SysVModel):
    pass


class AMD64SysVKillpg(Killpg, AMD64SysVModel):
    pass


class AMD64SysVPthreadKill(PthreadKill, AMD64SysVModel):
    pass


class AMD64SysVPthreadSigmask(PthreadSigmask, AMD64SysVModel):
    pass


class AMD64SysVSigaction(Sigaction, AMD64SysVModel):
    pass


class AMD64SysVSigaddset(Sigaddset, AMD64SysVModel):
    pass


class AMD64SysVSigaltstack(Sigaltstack, AMD64SysVModel):
    pass


class AMD64SysVSigdelset(Sigdelset, AMD64SysVModel):
    pass


class AMD64SysVSigemptyset(Sigemptyset, AMD64SysVModel):
    pass


class AMD64SysVSigfillset(Sigfillset, AMD64SysVModel):
    pass


class AMD64SysVSighold(Sighold, AMD64SysVModel):
    pass


class AMD64SysVSigignore(Sigignore, AMD64SysVModel):
    pass


class AMD64SysVSiginterrupt(Siginterrupt, AMD64SysVModel):
    pass


class AMD64SysVSigismember(Sigismember, AMD64SysVModel):
    pass


class AMD64SysVSigpause(Sigpause, AMD64SysVModel):
    pass


class AMD64SysVSigpending(Sigpending, AMD64SysVModel):
    pass


class AMD64SysVSigprocmask(Sigprocmask, AMD64SysVModel):
    pass


class AMD64SysVSigqueue(Sigqueue, AMD64SysVModel):
    pass


class AMD64SysVSigrelse(Sigrelse, AMD64SysVModel):
    pass


class AMD64SysVSigset(Sigset, AMD64SysVModel):
    pass


class AMD64SysVSigsuspend(Sigsuspend, AMD64SysVModel):
    pass


class AMD64SysVSigtimedwait(Sigtimedwait, AMD64SysVModel):
    pass


class AMD64SysVSigwait(Sigwait, AMD64SysVModel):
    pass


class AMD64SysVSigwaitinfo(Sigwaitinfo, AMD64SysVModel):
    pass


__all__ = [
    "AMD64SysVBsdSignal",
    "AMD64SysVKill",
    "AMD64SysVKillpg",
    "AMD64SysVPthreadKill",
    "AMD64SysVPthreadSigmask",
    "AMD64SysVSigaction",
    "AMD64SysVSigaddset",
    "AMD64SysVSigaltstack",
    "AMD64SysVSigdelset",
    "AMD64SysVSigemptyset",
    "AMD64SysVSigfillset",
    "AMD64SysVSighold",
    "AMD64SysVSigignore",
    "AMD64SysVSiginterrupt",
    "AMD64SysVSigismember",
    "AMD64SysVSigpause",
    "AMD64SysVSigpending",
    "AMD64SysVSigprocmask",
    "AMD64SysVSigqueue",
    "AMD64SysVSigrelse",
    "AMD64SysVSigset",
    "AMD64SysVSigsuspend",
    "AMD64SysVSigtimedwait",
    "AMD64SysVSigwait",
    "AMD64SysVSigwaitinfo",
]
