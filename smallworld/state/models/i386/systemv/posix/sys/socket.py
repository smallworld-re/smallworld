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
from ...systemv import I386SysVModel


class I386SysVAccept(Accept, I386SysVModel):
    pass


class I386SysVBind(Bind, I386SysVModel):
    pass


class I386SysVConnect(Connect, I386SysVModel):
    pass


class I386SysVGetpeername(Getpeername, I386SysVModel):
    pass


class I386SysVGetsockname(Getsockname, I386SysVModel):
    pass


class I386SysVGetsockopt(Getsockopt, I386SysVModel):
    pass


class I386SysVListen(Listen, I386SysVModel):
    pass


class I386SysVRecv(Recv, I386SysVModel):
    pass


class I386SysVRecvfrom(Recvfrom, I386SysVModel):
    pass


class I386SysVRecvmsg(Recvmsg, I386SysVModel):
    pass


class I386SysVSend(Send, I386SysVModel):
    pass


class I386SysVSendmsg(Sendmsg, I386SysVModel):
    pass


class I386SysVSendto(Sendto, I386SysVModel):
    pass


class I386SysVSetsockopt(Setsockopt, I386SysVModel):
    pass


class I386SysVShutdown(Shutdown, I386SysVModel):
    pass


class I386SysVSocket(Socket, I386SysVModel):
    pass


class I386SysVSocketpair(Socketpair, I386SysVModel):
    pass


__all__ = [
    "I386SysVAccept",
    "I386SysVBind",
    "I386SysVConnect",
    "I386SysVGetpeername",
    "I386SysVGetsockname",
    "I386SysVGetsockopt",
    "I386SysVListen",
    "I386SysVRecv",
    "I386SysVRecvfrom",
    "I386SysVRecvmsg",
    "I386SysVSend",
    "I386SysVSendmsg",
    "I386SysVSendto",
    "I386SysVSetsockopt",
    "I386SysVShutdown",
    "I386SysVSocket",
    "I386SysVSocketpair",
]
