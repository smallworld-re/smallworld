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
from ...systemv import AMD64SysVModel


class AMD64SysVAccept(Accept, AMD64SysVModel):
    pass


class AMD64SysVBind(Bind, AMD64SysVModel):
    pass


class AMD64SysVConnect(Connect, AMD64SysVModel):
    pass


class AMD64SysVGetpeername(Getpeername, AMD64SysVModel):
    pass


class AMD64SysVGetsockname(Getsockname, AMD64SysVModel):
    pass


class AMD64SysVGetsockopt(Getsockopt, AMD64SysVModel):
    pass


class AMD64SysVListen(Listen, AMD64SysVModel):
    pass


class AMD64SysVRecv(Recv, AMD64SysVModel):
    pass


class AMD64SysVRecvfrom(Recvfrom, AMD64SysVModel):
    pass


class AMD64SysVRecvmsg(Recvmsg, AMD64SysVModel):
    pass


class AMD64SysVSend(Send, AMD64SysVModel):
    pass


class AMD64SysVSendmsg(Sendmsg, AMD64SysVModel):
    pass


class AMD64SysVSendto(Sendto, AMD64SysVModel):
    pass


class AMD64SysVSetsockopt(Setsockopt, AMD64SysVModel):
    pass


class AMD64SysVShutdown(Shutdown, AMD64SysVModel):
    pass


class AMD64SysVSocket(Socket, AMD64SysVModel):
    pass


class AMD64SysVSocketpair(Socketpair, AMD64SysVModel):
    pass


__all__ = [
    "AMD64SysVAccept",
    "AMD64SysVBind",
    "AMD64SysVConnect",
    "AMD64SysVGetpeername",
    "AMD64SysVGetsockname",
    "AMD64SysVGetsockopt",
    "AMD64SysVListen",
    "AMD64SysVRecv",
    "AMD64SysVRecvfrom",
    "AMD64SysVRecvmsg",
    "AMD64SysVSend",
    "AMD64SysVSendmsg",
    "AMD64SysVSendto",
    "AMD64SysVSetsockopt",
    "AMD64SysVShutdown",
    "AMD64SysVSocket",
    "AMD64SysVSocketpair",
]
