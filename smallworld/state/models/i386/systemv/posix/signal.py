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
from ..systemv import I386SysVModel


class I386SysVBsdSignal(BsdSignal, I386SysVModel):
    pass


class I386SysVKill(Kill, I386SysVModel):
    pass


class I386SysVKillpg(Killpg, I386SysVModel):
    pass


class I386SysVPthreadKill(PthreadKill, I386SysVModel):
    pass


class I386SysVPthreadSigmask(PthreadSigmask, I386SysVModel):
    pass


class I386SysVSigaction(Sigaction, I386SysVModel):
    pass


class I386SysVSigaddset(Sigaddset, I386SysVModel):
    pass


class I386SysVSigaltstack(Sigaltstack, I386SysVModel):
    pass


class I386SysVSigdelset(Sigdelset, I386SysVModel):
    pass


class I386SysVSigemptyset(Sigemptyset, I386SysVModel):
    pass


class I386SysVSigfillset(Sigfillset, I386SysVModel):
    pass


class I386SysVSighold(Sighold, I386SysVModel):
    pass


class I386SysVSigignore(Sigignore, I386SysVModel):
    pass


class I386SysVSiginterrupt(Siginterrupt, I386SysVModel):
    pass


class I386SysVSigismember(Sigismember, I386SysVModel):
    pass


class I386SysVSigpause(Sigpause, I386SysVModel):
    pass


class I386SysVSigpending(Sigpending, I386SysVModel):
    pass


class I386SysVSigprocmask(Sigprocmask, I386SysVModel):
    pass


class I386SysVSigqueue(Sigqueue, I386SysVModel):
    pass


class I386SysVSigrelse(Sigrelse, I386SysVModel):
    pass


class I386SysVSigset(Sigset, I386SysVModel):
    pass


class I386SysVSigsuspend(Sigsuspend, I386SysVModel):
    pass


class I386SysVSigtimedwait(Sigtimedwait, I386SysVModel):
    pass


class I386SysVSigwait(Sigwait, I386SysVModel):
    pass


class I386SysVSigwaitinfo(Sigwaitinfo, I386SysVModel):
    pass


__all__ = [
    "I386SysVBsdSignal",
    "I386SysVKill",
    "I386SysVKillpg",
    "I386SysVPthreadKill",
    "I386SysVPthreadSigmask",
    "I386SysVSigaction",
    "I386SysVSigaddset",
    "I386SysVSigaltstack",
    "I386SysVSigdelset",
    "I386SysVSigemptyset",
    "I386SysVSigfillset",
    "I386SysVSighold",
    "I386SysVSigignore",
    "I386SysVSiginterrupt",
    "I386SysVSigismember",
    "I386SysVSigpause",
    "I386SysVSigpending",
    "I386SysVSigprocmask",
    "I386SysVSigqueue",
    "I386SysVSigrelse",
    "I386SysVSigset",
    "I386SysVSigsuspend",
    "I386SysVSigtimedwait",
    "I386SysVSigwait",
    "I386SysVSigwaitinfo",
]
