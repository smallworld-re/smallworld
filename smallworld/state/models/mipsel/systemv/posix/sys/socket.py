from .....posix.socket import (
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
from ...systemv import MIPSELSysVModel


class MIPSELSysVAccept(Accept, MIPSELSysVModel):
    pass


class MIPSELSysVBind(Bind, MIPSELSysVModel):
    pass


class MIPSELSysVConnect(Connect, MIPSELSysVModel):
    pass


class MIPSELSysVGetpeername(Getpeername, MIPSELSysVModel):
    pass


class MIPSELSysVGetsockname(Getsockname, MIPSELSysVModel):
    pass


class MIPSELSysVGetsockopt(Getsockopt, MIPSELSysVModel):
    pass


class MIPSELSysVListen(Listen, MIPSELSysVModel):
    pass


class MIPSELSysVRecv(Recv, MIPSELSysVModel):
    pass


class MIPSELSysVRecvfrom(Recvfrom, MIPSELSysVModel):
    pass


class MIPSELSysVRecvmsg(Recvmsg, MIPSELSysVModel):
    pass


class MIPSELSysVSend(Send, MIPSELSysVModel):
    pass


class MIPSELSysVSendmsg(Sendmsg, MIPSELSysVModel):
    pass


class MIPSELSysVSendto(Sendto, MIPSELSysVModel):
    pass


class MIPSELSysVSetsockopt(Setsockopt, MIPSELSysVModel):
    pass


class MIPSELSysVShutdown(Shutdown, MIPSELSysVModel):
    pass


class MIPSELSysVSocket(Socket, MIPSELSysVModel):
    pass


class MIPSELSysVSocketpair(Socketpair, MIPSELSysVModel):
    pass


__all__ = [
    "MIPSELSysVAccept",
    "MIPSELSysVBind",
    "MIPSELSysVConnect",
    "MIPSELSysVGetpeername",
    "MIPSELSysVGetsockname",
    "MIPSELSysVGetsockopt",
    "MIPSELSysVListen",
    "MIPSELSysVRecv",
    "MIPSELSysVRecvfrom",
    "MIPSELSysVRecvmsg",
    "MIPSELSysVSend",
    "MIPSELSysVSendmsg",
    "MIPSELSysVSendto",
    "MIPSELSysVSetsockopt",
    "MIPSELSysVShutdown",
    "MIPSELSysVSocket",
    "MIPSELSysVSocketpair",
]
