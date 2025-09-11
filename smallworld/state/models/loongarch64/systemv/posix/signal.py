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
from ..systemv import LoongArch64SysVModel


class LoongArch64SysVBsdSignal(BsdSignal, LoongArch64SysVModel):
    pass


class LoongArch64SysVKill(Kill, LoongArch64SysVModel):
    pass


class LoongArch64SysVKillpg(Killpg, LoongArch64SysVModel):
    pass


class LoongArch64SysVPthreadKill(PthreadKill, LoongArch64SysVModel):
    pass


class LoongArch64SysVPthreadSigmask(PthreadSigmask, LoongArch64SysVModel):
    pass


class LoongArch64SysVSigaction(Sigaction, LoongArch64SysVModel):
    pass


class LoongArch64SysVSigaddset(Sigaddset, LoongArch64SysVModel):
    pass


class LoongArch64SysVSigaltstack(Sigaltstack, LoongArch64SysVModel):
    pass


class LoongArch64SysVSigdelset(Sigdelset, LoongArch64SysVModel):
    pass


class LoongArch64SysVSigemptyset(Sigemptyset, LoongArch64SysVModel):
    pass


class LoongArch64SysVSigfillset(Sigfillset, LoongArch64SysVModel):
    pass


class LoongArch64SysVSighold(Sighold, LoongArch64SysVModel):
    pass


class LoongArch64SysVSigignore(Sigignore, LoongArch64SysVModel):
    pass


class LoongArch64SysVSiginterrupt(Siginterrupt, LoongArch64SysVModel):
    pass


class LoongArch64SysVSigismember(Sigismember, LoongArch64SysVModel):
    pass


class LoongArch64SysVSigpause(Sigpause, LoongArch64SysVModel):
    pass


class LoongArch64SysVSigpending(Sigpending, LoongArch64SysVModel):
    pass


class LoongArch64SysVSigprocmask(Sigprocmask, LoongArch64SysVModel):
    pass


class LoongArch64SysVSigqueue(Sigqueue, LoongArch64SysVModel):
    pass


class LoongArch64SysVSigrelse(Sigrelse, LoongArch64SysVModel):
    pass


class LoongArch64SysVSigset(Sigset, LoongArch64SysVModel):
    pass


class LoongArch64SysVSigsuspend(Sigsuspend, LoongArch64SysVModel):
    pass


class LoongArch64SysVSigtimedwait(Sigtimedwait, LoongArch64SysVModel):
    pass


class LoongArch64SysVSigwait(Sigwait, LoongArch64SysVModel):
    pass


class LoongArch64SysVSigwaitinfo(Sigwaitinfo, LoongArch64SysVModel):
    pass


__all__ = [
    "LoongArch64SysVBsdSignal",
    "LoongArch64SysVKill",
    "LoongArch64SysVKillpg",
    "LoongArch64SysVPthreadKill",
    "LoongArch64SysVPthreadSigmask",
    "LoongArch64SysVSigaction",
    "LoongArch64SysVSigaddset",
    "LoongArch64SysVSigaltstack",
    "LoongArch64SysVSigdelset",
    "LoongArch64SysVSigemptyset",
    "LoongArch64SysVSigfillset",
    "LoongArch64SysVSighold",
    "LoongArch64SysVSigignore",
    "LoongArch64SysVSiginterrupt",
    "LoongArch64SysVSigismember",
    "LoongArch64SysVSigpause",
    "LoongArch64SysVSigpending",
    "LoongArch64SysVSigprocmask",
    "LoongArch64SysVSigqueue",
    "LoongArch64SysVSigrelse",
    "LoongArch64SysVSigset",
    "LoongArch64SysVSigsuspend",
    "LoongArch64SysVSigtimedwait",
    "LoongArch64SysVSigwait",
    "LoongArch64SysVSigwaitinfo",
]
