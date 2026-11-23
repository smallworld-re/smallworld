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
from ..systemv import RiscV32SysVModel


class RiscV32SysVBsdSignal(BsdSignal, RiscV32SysVModel):
    pass


class RiscV32SysVKill(Kill, RiscV32SysVModel):
    pass


class RiscV32SysVKillpg(Killpg, RiscV32SysVModel):
    pass


class RiscV32SysVPthreadKill(PthreadKill, RiscV32SysVModel):
    pass


class RiscV32SysVPthreadSigmask(PthreadSigmask, RiscV32SysVModel):
    pass


class RiscV32SysVSigaction(Sigaction, RiscV32SysVModel):
    pass


class RiscV32SysVSigaddset(Sigaddset, RiscV32SysVModel):
    pass


class RiscV32SysVSigaltstack(Sigaltstack, RiscV32SysVModel):
    pass


class RiscV32SysVSigdelset(Sigdelset, RiscV32SysVModel):
    pass


class RiscV32SysVSigemptyset(Sigemptyset, RiscV32SysVModel):
    pass


class RiscV32SysVSigfillset(Sigfillset, RiscV32SysVModel):
    pass


class RiscV32SysVSighold(Sighold, RiscV32SysVModel):
    pass


class RiscV32SysVSigignore(Sigignore, RiscV32SysVModel):
    pass


class RiscV32SysVSiginterrupt(Siginterrupt, RiscV32SysVModel):
    pass


class RiscV32SysVSigismember(Sigismember, RiscV32SysVModel):
    pass


class RiscV32SysVSigpause(Sigpause, RiscV32SysVModel):
    pass


class RiscV32SysVSigpending(Sigpending, RiscV32SysVModel):
    pass


class RiscV32SysVSigprocmask(Sigprocmask, RiscV32SysVModel):
    pass


class RiscV32SysVSigqueue(Sigqueue, RiscV32SysVModel):
    pass


class RiscV32SysVSigrelse(Sigrelse, RiscV32SysVModel):
    pass


class RiscV32SysVSigset(Sigset, RiscV32SysVModel):
    pass


class RiscV32SysVSigsuspend(Sigsuspend, RiscV32SysVModel):
    pass


class RiscV32SysVSigtimedwait(Sigtimedwait, RiscV32SysVModel):
    pass


class RiscV32SysVSigwait(Sigwait, RiscV32SysVModel):
    pass


class RiscV32SysVSigwaitinfo(Sigwaitinfo, RiscV32SysVModel):
    pass


__all__ = [
    "RiscV32SysVBsdSignal",
    "RiscV32SysVKill",
    "RiscV32SysVKillpg",
    "RiscV32SysVPthreadKill",
    "RiscV32SysVPthreadSigmask",
    "RiscV32SysVSigaction",
    "RiscV32SysVSigaddset",
    "RiscV32SysVSigaltstack",
    "RiscV32SysVSigdelset",
    "RiscV32SysVSigemptyset",
    "RiscV32SysVSigfillset",
    "RiscV32SysVSighold",
    "RiscV32SysVSigignore",
    "RiscV32SysVSiginterrupt",
    "RiscV32SysVSigismember",
    "RiscV32SysVSigpause",
    "RiscV32SysVSigpending",
    "RiscV32SysVSigprocmask",
    "RiscV32SysVSigqueue",
    "RiscV32SysVSigrelse",
    "RiscV32SysVSigset",
    "RiscV32SysVSigsuspend",
    "RiscV32SysVSigtimedwait",
    "RiscV32SysVSigwait",
    "RiscV32SysVSigwaitinfo",
]
