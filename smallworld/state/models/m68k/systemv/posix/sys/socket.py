from .....posix.sys.socket import (
    Accept,
    Bind,
    Connect,
    Getpeername,
    Getsockname,
    Getsockopt,
    Listen,
    Recv,
    Recvfrom,
    Recvmsg,
    Send,
    Sendmsg,
    Sendto,
    Setsockopt,
    Shutdown,
    Socket,
    Socketpair,
)
from ...systemv import M68KSysVModel


class M68KSysVAccept(Accept, M68KSysVModel):
    pass


class M68KSysVBind(Bind, M68KSysVModel):
    pass


class M68KSysVConnect(Connect, M68KSysVModel):
    pass


class M68KSysVGetpeername(Getpeername, M68KSysVModel):
    pass


class M68KSysVGetsockname(Getsockname, M68KSysVModel):
    pass


class M68KSysVGetsockopt(Getsockopt, M68KSysVModel):
    pass


class M68KSysVListen(Listen, M68KSysVModel):
    pass


class M68KSysVRecv(Recv, M68KSysVModel):
    pass


class M68KSysVRecvfrom(Recvfrom, M68KSysVModel):
    pass


class M68KSysVRecvmsg(Recvmsg, M68KSysVModel):
    pass


class M68KSysVSend(Send, M68KSysVModel):
    pass


class M68KSysVSendmsg(Sendmsg, M68KSysVModel):
    pass


class M68KSysVSendto(Sendto, M68KSysVModel):
    pass


class M68KSysVSetsockopt(Setsockopt, M68KSysVModel):
    pass


class M68KSysVShutdown(Shutdown, M68KSysVModel):
    pass


class M68KSysVSocket(Socket, M68KSysVModel):
    pass


class M68KSysVSocketpair(Socketpair, M68KSysVModel):
    pass


__all__ = [
    "M68KSysVAccept",
    "M68KSysVBind",
    "M68KSysVConnect",
    "M68KSysVGetpeername",
    "M68KSysVGetsockname",
    "M68KSysVGetsockopt",
    "M68KSysVListen",
    "M68KSysVRecv",
    "M68KSysVRecvfrom",
    "M68KSysVRecvmsg",
    "M68KSysVSend",
    "M68KSysVSendmsg",
    "M68KSysVSendto",
    "M68KSysVSetsockopt",
    "M68KSysVShutdown",
    "M68KSysVSocket",
    "M68KSysVSocketpair",
]
