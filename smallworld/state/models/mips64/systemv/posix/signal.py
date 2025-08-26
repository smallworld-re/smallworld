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
from ..systemv import MIPS64SysVModel


class MIPS64SysVBsdSignal(BsdSignal, MIPS64SysVModel):
    pass


class MIPS64SysVKill(Kill, MIPS64SysVModel):
    pass


class MIPS64SysVKillpg(Killpg, MIPS64SysVModel):
    pass


class MIPS64SysVPthreadKill(PthreadKill, MIPS64SysVModel):
    pass


class MIPS64SysVPthreadSigmask(PthreadSigmask, MIPS64SysVModel):
    pass


class MIPS64SysVSigaction(Sigaction, MIPS64SysVModel):
    pass


class MIPS64SysVSigaddset(Sigaddset, MIPS64SysVModel):
    pass


class MIPS64SysVSigaltstack(Sigaltstack, MIPS64SysVModel):
    pass


class MIPS64SysVSigdelset(Sigdelset, MIPS64SysVModel):
    pass


class MIPS64SysVSigemptyset(Sigemptyset, MIPS64SysVModel):
    pass


class MIPS64SysVSigfillset(Sigfillset, MIPS64SysVModel):
    pass


class MIPS64SysVSighold(Sighold, MIPS64SysVModel):
    pass


class MIPS64SysVSigignore(Sigignore, MIPS64SysVModel):
    pass


class MIPS64SysVSiginterrupt(Siginterrupt, MIPS64SysVModel):
    pass


class MIPS64SysVSigismember(Sigismember, MIPS64SysVModel):
    pass


class MIPS64SysVSigpause(Sigpause, MIPS64SysVModel):
    pass


class MIPS64SysVSigpending(Sigpending, MIPS64SysVModel):
    pass


class MIPS64SysVSigprocmask(Sigprocmask, MIPS64SysVModel):
    pass


class MIPS64SysVSigqueue(Sigqueue, MIPS64SysVModel):
    pass


class MIPS64SysVSigrelse(Sigrelse, MIPS64SysVModel):
    pass


class MIPS64SysVSigset(Sigset, MIPS64SysVModel):
    pass


class MIPS64SysVSigsuspend(Sigsuspend, MIPS64SysVModel):
    pass


class MIPS64SysVSigtimedwait(Sigtimedwait, MIPS64SysVModel):
    pass


class MIPS64SysVSigwait(Sigwait, MIPS64SysVModel):
    pass


class MIPS64SysVSigwaitinfo(Sigwaitinfo, MIPS64SysVModel):
    pass


__all__ = [
    "MIPS64SysVBsdSignal",
    "MIPS64SysVKill",
    "MIPS64SysVKillpg",
    "MIPS64SysVPthreadKill",
    "MIPS64SysVPthreadSigmask",
    "MIPS64SysVSigaction",
    "MIPS64SysVSigaddset",
    "MIPS64SysVSigaltstack",
    "MIPS64SysVSigdelset",
    "MIPS64SysVSigemptyset",
    "MIPS64SysVSigfillset",
    "MIPS64SysVSighold",
    "MIPS64SysVSigignore",
    "MIPS64SysVSiginterrupt",
    "MIPS64SysVSigismember",
    "MIPS64SysVSigpause",
    "MIPS64SysVSigpending",
    "MIPS64SysVSigprocmask",
    "MIPS64SysVSigqueue",
    "MIPS64SysVSigrelse",
    "MIPS64SysVSigset",
    "MIPS64SysVSigsuspend",
    "MIPS64SysVSigtimedwait",
    "MIPS64SysVSigwait",
    "MIPS64SysVSigwaitinfo",
]
