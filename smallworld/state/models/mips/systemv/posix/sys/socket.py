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
from ...systemv import MIPSSysVModel


class MIPSSysVAccept(Accept, MIPSSysVModel):
    pass


class MIPSSysVBind(Bind, MIPSSysVModel):
    pass


class MIPSSysVConnect(Connect, MIPSSysVModel):
    pass


class MIPSSysVGetpeername(Getpeername, MIPSSysVModel):
    pass


class MIPSSysVGetsockname(Getsockname, MIPSSysVModel):
    pass


class MIPSSysVGetsockopt(Getsockopt, MIPSSysVModel):
    pass


class MIPSSysVListen(Listen, MIPSSysVModel):
    pass


class MIPSSysVRecv(Recv, MIPSSysVModel):
    pass


class MIPSSysVRecvfrom(Recvfrom, MIPSSysVModel):
    pass


class MIPSSysVRecvmsg(Recvmsg, MIPSSysVModel):
    pass


class MIPSSysVSend(Send, MIPSSysVModel):
    pass


class MIPSSysVSendmsg(Sendmsg, MIPSSysVModel):
    pass


class MIPSSysVSendto(Sendto, MIPSSysVModel):
    pass


class MIPSSysVSetsockopt(Setsockopt, MIPSSysVModel):
    pass


class MIPSSysVShutdown(Shutdown, MIPSSysVModel):
    pass


class MIPSSysVSocket(Socket, MIPSSysVModel):
    pass


class MIPSSysVSocketpair(Socketpair, MIPSSysVModel):
    pass


__all__ = [
    "MIPSSysVAccept",
    "MIPSSysVBind",
    "MIPSSysVConnect",
    "MIPSSysVGetpeername",
    "MIPSSysVGetsockname",
    "MIPSSysVGetsockopt",
    "MIPSSysVListen",
    "MIPSSysVRecv",
    "MIPSSysVRecvfrom",
    "MIPSSysVRecvmsg",
    "MIPSSysVSend",
    "MIPSSysVSendmsg",
    "MIPSSysVSendto",
    "MIPSSysVSetsockopt",
    "MIPSSysVShutdown",
    "MIPSSysVSocket",
    "MIPSSysVSocketpair",
]
