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
from ...systemv import AArch64V85ABESysVModel


class AArch64V85ABESysVAccept(Accept, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVBind(Bind, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVConnect(Connect, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVGetpeername(Getpeername, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVGetsockname(Getsockname, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVGetsockopt(Getsockopt, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVListen(Listen, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVRecv(Recv, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVRecvfrom(Recvfrom, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVRecvmsg(Recvmsg, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSend(Send, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSendmsg(Sendmsg, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSendto(Sendto, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSetsockopt(Setsockopt, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVShutdown(Shutdown, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSocket(Socket, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSocketpair(Socketpair, AArch64V85ABESysVModel):
    pass


__all__ = [
    "AArch64V85ABESysVAccept",
    "AArch64V85ABESysVBind",
    "AArch64V85ABESysVConnect",
    "AArch64V85ABESysVGetpeername",
    "AArch64V85ABESysVGetsockname",
    "AArch64V85ABESysVGetsockopt",
    "AArch64V85ABESysVListen",
    "AArch64V85ABESysVRecv",
    "AArch64V85ABESysVRecvfrom",
    "AArch64V85ABESysVRecvmsg",
    "AArch64V85ABESysVSend",
    "AArch64V85ABESysVSendmsg",
    "AArch64V85ABESysVSendto",
    "AArch64V85ABESysVSetsockopt",
    "AArch64V85ABESysVShutdown",
    "AArch64V85ABESysVSocket",
    "AArch64V85ABESysVSocketpair",
]
