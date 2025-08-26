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
from ..systemv import AArch64SysVModel


class AArch64SysVBsdSignal(BsdSignal, AArch64SysVModel):
    pass


class AArch64SysVKill(Kill, AArch64SysVModel):
    pass


class AArch64SysVKillpg(Killpg, AArch64SysVModel):
    pass


class AArch64SysVPthreadKill(PthreadKill, AArch64SysVModel):
    pass


class AArch64SysVPthreadSigmask(PthreadSigmask, AArch64SysVModel):
    pass


class AArch64SysVSigaction(Sigaction, AArch64SysVModel):
    pass


class AArch64SysVSigaddset(Sigaddset, AArch64SysVModel):
    pass


class AArch64SysVSigaltstack(Sigaltstack, AArch64SysVModel):
    pass


class AArch64SysVSigdelset(Sigdelset, AArch64SysVModel):
    pass


class AArch64SysVSigemptyset(Sigemptyset, AArch64SysVModel):
    pass


class AArch64SysVSigfillset(Sigfillset, AArch64SysVModel):
    pass


class AArch64SysVSighold(Sighold, AArch64SysVModel):
    pass


class AArch64SysVSigignore(Sigignore, AArch64SysVModel):
    pass


class AArch64SysVSiginterrupt(Siginterrupt, AArch64SysVModel):
    pass


class AArch64SysVSigismember(Sigismember, AArch64SysVModel):
    pass


class AArch64SysVSigpause(Sigpause, AArch64SysVModel):
    pass


class AArch64SysVSigpending(Sigpending, AArch64SysVModel):
    pass


class AArch64SysVSigprocmask(Sigprocmask, AArch64SysVModel):
    pass


class AArch64SysVSigqueue(Sigqueue, AArch64SysVModel):
    pass


class AArch64SysVSigrelse(Sigrelse, AArch64SysVModel):
    pass


class AArch64SysVSigset(Sigset, AArch64SysVModel):
    pass


class AArch64SysVSigsuspend(Sigsuspend, AArch64SysVModel):
    pass


class AArch64SysVSigtimedwait(Sigtimedwait, AArch64SysVModel):
    pass


class AArch64SysVSigwait(Sigwait, AArch64SysVModel):
    pass


class AArch64SysVSigwaitinfo(Sigwaitinfo, AArch64SysVModel):
    pass


__all__ = [
    "AArch64SysVBsdSignal",
    "AArch64SysVKill",
    "AArch64SysVKillpg",
    "AArch64SysVPthreadKill",
    "AArch64SysVPthreadSigmask",
    "AArch64SysVSigaction",
    "AArch64SysVSigaddset",
    "AArch64SysVSigaltstack",
    "AArch64SysVSigdelset",
    "AArch64SysVSigemptyset",
    "AArch64SysVSigfillset",
    "AArch64SysVSighold",
    "AArch64SysVSigignore",
    "AArch64SysVSiginterrupt",
    "AArch64SysVSigismember",
    "AArch64SysVSigpause",
    "AArch64SysVSigpending",
    "AArch64SysVSigprocmask",
    "AArch64SysVSigqueue",
    "AArch64SysVSigrelse",
    "AArch64SysVSigset",
    "AArch64SysVSigsuspend",
    "AArch64SysVSigtimedwait",
    "AArch64SysVSigwait",
    "AArch64SysVSigwaitinfo",
]
