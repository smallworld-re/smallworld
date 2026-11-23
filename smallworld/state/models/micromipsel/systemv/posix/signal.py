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
from ..systemv import MicroMIPSELSysVModel


class MicroMIPSELSysVBsdSignal(BsdSignal, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVKill(Kill, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVKillpg(Killpg, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVPthreadKill(PthreadKill, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVPthreadSigmask(PthreadSigmask, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSigaction(Sigaction, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSigaddset(Sigaddset, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSigaltstack(Sigaltstack, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSigdelset(Sigdelset, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSigemptyset(Sigemptyset, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSigfillset(Sigfillset, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSighold(Sighold, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSigignore(Sigignore, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSiginterrupt(Siginterrupt, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSigismember(Sigismember, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSigpause(Sigpause, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSigpending(Sigpending, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSigprocmask(Sigprocmask, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSigqueue(Sigqueue, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSigrelse(Sigrelse, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSigset(Sigset, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSigsuspend(Sigsuspend, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSigtimedwait(Sigtimedwait, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSigwait(Sigwait, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSigwaitinfo(Sigwaitinfo, MicroMIPSELSysVModel):
    pass


__all__ = [
    "MicroMIPSELSysVBsdSignal",
    "MicroMIPSELSysVKill",
    "MicroMIPSELSysVKillpg",
    "MicroMIPSELSysVPthreadKill",
    "MicroMIPSELSysVPthreadSigmask",
    "MicroMIPSELSysVSigaction",
    "MicroMIPSELSysVSigaddset",
    "MicroMIPSELSysVSigaltstack",
    "MicroMIPSELSysVSigdelset",
    "MicroMIPSELSysVSigemptyset",
    "MicroMIPSELSysVSigfillset",
    "MicroMIPSELSysVSighold",
    "MicroMIPSELSysVSigignore",
    "MicroMIPSELSysVSiginterrupt",
    "MicroMIPSELSysVSigismember",
    "MicroMIPSELSysVSigpause",
    "MicroMIPSELSysVSigpending",
    "MicroMIPSELSysVSigprocmask",
    "MicroMIPSELSysVSigqueue",
    "MicroMIPSELSysVSigrelse",
    "MicroMIPSELSysVSigset",
    "MicroMIPSELSysVSigsuspend",
    "MicroMIPSELSysVSigtimedwait",
    "MicroMIPSELSysVSigwait",
    "MicroMIPSELSysVSigwaitinfo",
]
