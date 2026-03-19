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
from ..systemv import M68KSysVModel


class M68KSysVBsdSignal(BsdSignal, M68KSysVModel):
    pass


class M68KSysVKill(Kill, M68KSysVModel):
    pass


class M68KSysVKillpg(Killpg, M68KSysVModel):
    pass


class M68KSysVPthreadKill(PthreadKill, M68KSysVModel):
    pass


class M68KSysVPthreadSigmask(PthreadSigmask, M68KSysVModel):
    pass


class M68KSysVSigaction(Sigaction, M68KSysVModel):
    pass


class M68KSysVSigaddset(Sigaddset, M68KSysVModel):
    pass


class M68KSysVSigaltstack(Sigaltstack, M68KSysVModel):
    pass


class M68KSysVSigdelset(Sigdelset, M68KSysVModel):
    pass


class M68KSysVSigemptyset(Sigemptyset, M68KSysVModel):
    pass


class M68KSysVSigfillset(Sigfillset, M68KSysVModel):
    pass


class M68KSysVSighold(Sighold, M68KSysVModel):
    pass


class M68KSysVSigignore(Sigignore, M68KSysVModel):
    pass


class M68KSysVSiginterrupt(Siginterrupt, M68KSysVModel):
    pass


class M68KSysVSigismember(Sigismember, M68KSysVModel):
    pass


class M68KSysVSigpause(Sigpause, M68KSysVModel):
    pass


class M68KSysVSigpending(Sigpending, M68KSysVModel):
    pass


class M68KSysVSigprocmask(Sigprocmask, M68KSysVModel):
    pass


class M68KSysVSigqueue(Sigqueue, M68KSysVModel):
    pass


class M68KSysVSigrelse(Sigrelse, M68KSysVModel):
    pass


class M68KSysVSigset(Sigset, M68KSysVModel):
    pass


class M68KSysVSigsuspend(Sigsuspend, M68KSysVModel):
    pass


class M68KSysVSigtimedwait(Sigtimedwait, M68KSysVModel):
    pass


class M68KSysVSigwait(Sigwait, M68KSysVModel):
    pass


class M68KSysVSigwaitinfo(Sigwaitinfo, M68KSysVModel):
    pass


__all__ = [
    "M68KSysVBsdSignal",
    "M68KSysVKill",
    "M68KSysVKillpg",
    "M68KSysVPthreadKill",
    "M68KSysVPthreadSigmask",
    "M68KSysVSigaction",
    "M68KSysVSigaddset",
    "M68KSysVSigaltstack",
    "M68KSysVSigdelset",
    "M68KSysVSigemptyset",
    "M68KSysVSigfillset",
    "M68KSysVSighold",
    "M68KSysVSigignore",
    "M68KSysVSiginterrupt",
    "M68KSysVSigismember",
    "M68KSysVSigpause",
    "M68KSysVSigpending",
    "M68KSysVSigprocmask",
    "M68KSysVSigqueue",
    "M68KSysVSigrelse",
    "M68KSysVSigset",
    "M68KSysVSigsuspend",
    "M68KSysVSigtimedwait",
    "M68KSysVSigwait",
    "M68KSysVSigwaitinfo",
]
