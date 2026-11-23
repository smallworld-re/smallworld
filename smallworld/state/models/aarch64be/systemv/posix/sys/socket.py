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
from ...systemv import AArch64BESysVModel


class AArch64BESysVAccept(Accept, AArch64BESysVModel):
    pass


class AArch64BESysVBind(Bind, AArch64BESysVModel):
    pass


class AArch64BESysVConnect(Connect, AArch64BESysVModel):
    pass


class AArch64BESysVGetpeername(Getpeername, AArch64BESysVModel):
    pass


class AArch64BESysVGetsockname(Getsockname, AArch64BESysVModel):
    pass


class AArch64BESysVGetsockopt(Getsockopt, AArch64BESysVModel):
    pass


class AArch64BESysVListen(Listen, AArch64BESysVModel):
    pass


class AArch64BESysVRecv(Recv, AArch64BESysVModel):
    pass


class AArch64BESysVRecvfrom(Recvfrom, AArch64BESysVModel):
    pass


class AArch64BESysVRecvmsg(Recvmsg, AArch64BESysVModel):
    pass


class AArch64BESysVSend(Send, AArch64BESysVModel):
    pass


class AArch64BESysVSendmsg(Sendmsg, AArch64BESysVModel):
    pass


class AArch64BESysVSendto(Sendto, AArch64BESysVModel):
    pass


class AArch64BESysVSetsockopt(Setsockopt, AArch64BESysVModel):
    pass


class AArch64BESysVShutdown(Shutdown, AArch64BESysVModel):
    pass


class AArch64BESysVSocket(Socket, AArch64BESysVModel):
    pass


class AArch64BESysVSocketpair(Socketpair, AArch64BESysVModel):
    pass


__all__ = [
    "AArch64BESysVAccept",
    "AArch64BESysVBind",
    "AArch64BESysVConnect",
    "AArch64BESysVGetpeername",
    "AArch64BESysVGetsockname",
    "AArch64BESysVGetsockopt",
    "AArch64BESysVListen",
    "AArch64BESysVRecv",
    "AArch64BESysVRecvfrom",
    "AArch64BESysVRecvmsg",
    "AArch64BESysVSend",
    "AArch64BESysVSendmsg",
    "AArch64BESysVSendto",
    "AArch64BESysVSetsockopt",
    "AArch64BESysVShutdown",
    "AArch64BESysVSocket",
    "AArch64BESysVSocketpair",
]
