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
from ..systemv import MIPS64ELSysVModel


class MIPS64ELSysVBsdSignal(BsdSignal, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVKill(Kill, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVKillpg(Killpg, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVPthreadKill(PthreadKill, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVPthreadSigmask(PthreadSigmask, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSigaction(Sigaction, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSigaddset(Sigaddset, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSigaltstack(Sigaltstack, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSigdelset(Sigdelset, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSigemptyset(Sigemptyset, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSigfillset(Sigfillset, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSighold(Sighold, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSigignore(Sigignore, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSiginterrupt(Siginterrupt, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSigismember(Sigismember, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSigpause(Sigpause, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSigpending(Sigpending, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSigprocmask(Sigprocmask, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSigqueue(Sigqueue, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSigrelse(Sigrelse, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSigset(Sigset, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSigsuspend(Sigsuspend, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSigtimedwait(Sigtimedwait, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSigwait(Sigwait, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSigwaitinfo(Sigwaitinfo, MIPS64ELSysVModel):
    pass


__all__ = [
    "MIPS64ELSysVBsdSignal",
    "MIPS64ELSysVKill",
    "MIPS64ELSysVKillpg",
    "MIPS64ELSysVPthreadKill",
    "MIPS64ELSysVPthreadSigmask",
    "MIPS64ELSysVSigaction",
    "MIPS64ELSysVSigaddset",
    "MIPS64ELSysVSigaltstack",
    "MIPS64ELSysVSigdelset",
    "MIPS64ELSysVSigemptyset",
    "MIPS64ELSysVSigfillset",
    "MIPS64ELSysVSighold",
    "MIPS64ELSysVSigignore",
    "MIPS64ELSysVSiginterrupt",
    "MIPS64ELSysVSigismember",
    "MIPS64ELSysVSigpause",
    "MIPS64ELSysVSigpending",
    "MIPS64ELSysVSigprocmask",
    "MIPS64ELSysVSigqueue",
    "MIPS64ELSysVSigrelse",
    "MIPS64ELSysVSigset",
    "MIPS64ELSysVSigsuspend",
    "MIPS64ELSysVSigtimedwait",
    "MIPS64ELSysVSigwait",
    "MIPS64ELSysVSigwaitinfo",
]
