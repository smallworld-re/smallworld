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
from ...systemv import AArch64V85ASysVModel


class AArch64V85ASysVAccept(Accept, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVBind(Bind, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVConnect(Connect, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVGetpeername(Getpeername, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVGetsockname(Getsockname, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVGetsockopt(Getsockopt, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVListen(Listen, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVRecv(Recv, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVRecvfrom(Recvfrom, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVRecvmsg(Recvmsg, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSend(Send, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSendmsg(Sendmsg, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSendto(Sendto, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSetsockopt(Setsockopt, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVShutdown(Shutdown, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSocket(Socket, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSocketpair(Socketpair, AArch64V85ASysVModel):
    pass


__all__ = [
    "AArch64V85ASysVAccept",
    "AArch64V85ASysVBind",
    "AArch64V85ASysVConnect",
    "AArch64V85ASysVGetpeername",
    "AArch64V85ASysVGetsockname",
    "AArch64V85ASysVGetsockopt",
    "AArch64V85ASysVListen",
    "AArch64V85ASysVRecv",
    "AArch64V85ASysVRecvfrom",
    "AArch64V85ASysVRecvmsg",
    "AArch64V85ASysVSend",
    "AArch64V85ASysVSendmsg",
    "AArch64V85ASysVSendto",
    "AArch64V85ASysVSetsockopt",
    "AArch64V85ASysVShutdown",
    "AArch64V85ASysVSocket",
    "AArch64V85ASysVSocketpair",
]
