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
from ..systemv import MIPSELSysVModel


class MIPSELSysVBsdSignal(BsdSignal, MIPSELSysVModel):
    pass


class MIPSELSysVKill(Kill, MIPSELSysVModel):
    pass


class MIPSELSysVKillpg(Killpg, MIPSELSysVModel):
    pass


class MIPSELSysVPthreadKill(PthreadKill, MIPSELSysVModel):
    pass


class MIPSELSysVPthreadSigmask(PthreadSigmask, MIPSELSysVModel):
    pass


class MIPSELSysVSigaction(Sigaction, MIPSELSysVModel):
    pass


class MIPSELSysVSigaddset(Sigaddset, MIPSELSysVModel):
    pass


class MIPSELSysVSigaltstack(Sigaltstack, MIPSELSysVModel):
    pass


class MIPSELSysVSigdelset(Sigdelset, MIPSELSysVModel):
    pass


class MIPSELSysVSigemptyset(Sigemptyset, MIPSELSysVModel):
    pass


class MIPSELSysVSigfillset(Sigfillset, MIPSELSysVModel):
    pass


class MIPSELSysVSighold(Sighold, MIPSELSysVModel):
    pass


class MIPSELSysVSigignore(Sigignore, MIPSELSysVModel):
    pass


class MIPSELSysVSiginterrupt(Siginterrupt, MIPSELSysVModel):
    pass


class MIPSELSysVSigismember(Sigismember, MIPSELSysVModel):
    pass


class MIPSELSysVSigpause(Sigpause, MIPSELSysVModel):
    pass


class MIPSELSysVSigpending(Sigpending, MIPSELSysVModel):
    pass


class MIPSELSysVSigprocmask(Sigprocmask, MIPSELSysVModel):
    pass


class MIPSELSysVSigqueue(Sigqueue, MIPSELSysVModel):
    pass


class MIPSELSysVSigrelse(Sigrelse, MIPSELSysVModel):
    pass


class MIPSELSysVSigset(Sigset, MIPSELSysVModel):
    pass


class MIPSELSysVSigsuspend(Sigsuspend, MIPSELSysVModel):
    pass


class MIPSELSysVSigtimedwait(Sigtimedwait, MIPSELSysVModel):
    pass


class MIPSELSysVSigwait(Sigwait, MIPSELSysVModel):
    pass


class MIPSELSysVSigwaitinfo(Sigwaitinfo, MIPSELSysVModel):
    pass


__all__ = [
    "MIPSELSysVBsdSignal",
    "MIPSELSysVKill",
    "MIPSELSysVKillpg",
    "MIPSELSysVPthreadKill",
    "MIPSELSysVPthreadSigmask",
    "MIPSELSysVSigaction",
    "MIPSELSysVSigaddset",
    "MIPSELSysVSigaltstack",
    "MIPSELSysVSigdelset",
    "MIPSELSysVSigemptyset",
    "MIPSELSysVSigfillset",
    "MIPSELSysVSighold",
    "MIPSELSysVSigignore",
    "MIPSELSysVSiginterrupt",
    "MIPSELSysVSigismember",
    "MIPSELSysVSigpause",
    "MIPSELSysVSigpending",
    "MIPSELSysVSigprocmask",
    "MIPSELSysVSigqueue",
    "MIPSELSysVSigrelse",
    "MIPSELSysVSigset",
    "MIPSELSysVSigsuspend",
    "MIPSELSysVSigtimedwait",
    "MIPSELSysVSigwait",
    "MIPSELSysVSigwaitinfo",
]
