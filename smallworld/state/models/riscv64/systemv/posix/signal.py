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
from ..systemv import RiscV64SysVModel


class RiscV64SysVBsdSignal(BsdSignal, RiscV64SysVModel):
    pass


class RiscV64SysVKill(Kill, RiscV64SysVModel):
    pass


class RiscV64SysVKillpg(Killpg, RiscV64SysVModel):
    pass


class RiscV64SysVPthreadKill(PthreadKill, RiscV64SysVModel):
    pass


class RiscV64SysVPthreadSigmask(PthreadSigmask, RiscV64SysVModel):
    pass


class RiscV64SysVSigaction(Sigaction, RiscV64SysVModel):
    pass


class RiscV64SysVSigaddset(Sigaddset, RiscV64SysVModel):
    pass


class RiscV64SysVSigaltstack(Sigaltstack, RiscV64SysVModel):
    pass


class RiscV64SysVSigdelset(Sigdelset, RiscV64SysVModel):
    pass


class RiscV64SysVSigemptyset(Sigemptyset, RiscV64SysVModel):
    pass


class RiscV64SysVSigfillset(Sigfillset, RiscV64SysVModel):
    pass


class RiscV64SysVSighold(Sighold, RiscV64SysVModel):
    pass


class RiscV64SysVSigignore(Sigignore, RiscV64SysVModel):
    pass


class RiscV64SysVSiginterrupt(Siginterrupt, RiscV64SysVModel):
    pass


class RiscV64SysVSigismember(Sigismember, RiscV64SysVModel):
    pass


class RiscV64SysVSigpause(Sigpause, RiscV64SysVModel):
    pass


class RiscV64SysVSigpending(Sigpending, RiscV64SysVModel):
    pass


class RiscV64SysVSigprocmask(Sigprocmask, RiscV64SysVModel):
    pass


class RiscV64SysVSigqueue(Sigqueue, RiscV64SysVModel):
    pass


class RiscV64SysVSigrelse(Sigrelse, RiscV64SysVModel):
    pass


class RiscV64SysVSigset(Sigset, RiscV64SysVModel):
    pass


class RiscV64SysVSigsuspend(Sigsuspend, RiscV64SysVModel):
    pass


class RiscV64SysVSigtimedwait(Sigtimedwait, RiscV64SysVModel):
    pass


class RiscV64SysVSigwait(Sigwait, RiscV64SysVModel):
    pass


class RiscV64SysVSigwaitinfo(Sigwaitinfo, RiscV64SysVModel):
    pass


__all__ = [
    "RiscV64SysVBsdSignal",
    "RiscV64SysVKill",
    "RiscV64SysVKillpg",
    "RiscV64SysVPthreadKill",
    "RiscV64SysVPthreadSigmask",
    "RiscV64SysVSigaction",
    "RiscV64SysVSigaddset",
    "RiscV64SysVSigaltstack",
    "RiscV64SysVSigdelset",
    "RiscV64SysVSigemptyset",
    "RiscV64SysVSigfillset",
    "RiscV64SysVSighold",
    "RiscV64SysVSigignore",
    "RiscV64SysVSiginterrupt",
    "RiscV64SysVSigismember",
    "RiscV64SysVSigpause",
    "RiscV64SysVSigpending",
    "RiscV64SysVSigprocmask",
    "RiscV64SysVSigqueue",
    "RiscV64SysVSigrelse",
    "RiscV64SysVSigset",
    "RiscV64SysVSigsuspend",
    "RiscV64SysVSigtimedwait",
    "RiscV64SysVSigwait",
    "RiscV64SysVSigwaitinfo",
]
