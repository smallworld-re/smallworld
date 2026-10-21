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
from ...systemv import SPARC32SysVModel


class SPARC32SysVAccept(Accept, SPARC32SysVModel):
    pass


class SPARC32SysVBind(Bind, SPARC32SysVModel):
    pass


class SPARC32SysVConnect(Connect, SPARC32SysVModel):
    pass


class SPARC32SysVGetpeername(Getpeername, SPARC32SysVModel):
    pass


class SPARC32SysVGetsockname(Getsockname, SPARC32SysVModel):
    pass


class SPARC32SysVGetsockopt(Getsockopt, SPARC32SysVModel):
    pass


class SPARC32SysVListen(Listen, SPARC32SysVModel):
    pass


class SPARC32SysVRecv(Recv, SPARC32SysVModel):
    pass


class SPARC32SysVRecvfrom(Recvfrom, SPARC32SysVModel):
    pass


class SPARC32SysVRecvmsg(Recvmsg, SPARC32SysVModel):
    pass


class SPARC32SysVSend(Send, SPARC32SysVModel):
    pass


class SPARC32SysVSendmsg(Sendmsg, SPARC32SysVModel):
    pass


class SPARC32SysVSendto(Sendto, SPARC32SysVModel):
    pass


class SPARC32SysVSetsockopt(Setsockopt, SPARC32SysVModel):
    pass


class SPARC32SysVShutdown(Shutdown, SPARC32SysVModel):
    pass


class SPARC32SysVSocket(Socket, SPARC32SysVModel):
    pass


class SPARC32SysVSocketpair(Socketpair, SPARC32SysVModel):
    pass


__all__ = [
    "SPARC32SysVAccept",
    "SPARC32SysVBind",
    "SPARC32SysVConnect",
    "SPARC32SysVGetpeername",
    "SPARC32SysVGetsockname",
    "SPARC32SysVGetsockopt",
    "SPARC32SysVListen",
    "SPARC32SysVRecv",
    "SPARC32SysVRecvfrom",
    "SPARC32SysVRecvmsg",
    "SPARC32SysVSend",
    "SPARC32SysVSendmsg",
    "SPARC32SysVSendto",
    "SPARC32SysVSetsockopt",
    "SPARC32SysVShutdown",
    "SPARC32SysVSocket",
    "SPARC32SysVSocketpair",
]
