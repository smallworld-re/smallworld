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
from ...systemv import MicroMIPSSysVModel


class MicroMIPSSysVAccept(Accept, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVBind(Bind, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVConnect(Connect, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVGetpeername(Getpeername, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVGetsockname(Getsockname, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVGetsockopt(Getsockopt, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVListen(Listen, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVRecv(Recv, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVRecvfrom(Recvfrom, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVRecvmsg(Recvmsg, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSend(Send, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSendmsg(Sendmsg, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSendto(Sendto, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSetsockopt(Setsockopt, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVShutdown(Shutdown, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSocket(Socket, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSocketpair(Socketpair, MicroMIPSSysVModel):
    pass


__all__ = [
    "MicroMIPSSysVAccept",
    "MicroMIPSSysVBind",
    "MicroMIPSSysVConnect",
    "MicroMIPSSysVGetpeername",
    "MicroMIPSSysVGetsockname",
    "MicroMIPSSysVGetsockopt",
    "MicroMIPSSysVListen",
    "MicroMIPSSysVRecv",
    "MicroMIPSSysVRecvfrom",
    "MicroMIPSSysVRecvmsg",
    "MicroMIPSSysVSend",
    "MicroMIPSSysVSendmsg",
    "MicroMIPSSysVSendto",
    "MicroMIPSSysVSetsockopt",
    "MicroMIPSSysVShutdown",
    "MicroMIPSSysVSocket",
    "MicroMIPSSysVSocketpair",
]
