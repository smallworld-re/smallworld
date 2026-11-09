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
from ...systemv import MicroMIPSELSysVModel


class MicroMIPSELSysVAccept(Accept, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVBind(Bind, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVConnect(Connect, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVGetpeername(Getpeername, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVGetsockname(Getsockname, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVGetsockopt(Getsockopt, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVListen(Listen, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVRecv(Recv, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVRecvfrom(Recvfrom, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVRecvmsg(Recvmsg, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSend(Send, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSendmsg(Sendmsg, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSendto(Sendto, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSetsockopt(Setsockopt, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVShutdown(Shutdown, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSocket(Socket, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSocketpair(Socketpair, MicroMIPSELSysVModel):
    pass


__all__ = [
    "MicroMIPSELSysVAccept",
    "MicroMIPSELSysVBind",
    "MicroMIPSELSysVConnect",
    "MicroMIPSELSysVGetpeername",
    "MicroMIPSELSysVGetsockname",
    "MicroMIPSELSysVGetsockopt",
    "MicroMIPSELSysVListen",
    "MicroMIPSELSysVRecv",
    "MicroMIPSELSysVRecvfrom",
    "MicroMIPSELSysVRecvmsg",
    "MicroMIPSELSysVSend",
    "MicroMIPSELSysVSendmsg",
    "MicroMIPSELSysVSendto",
    "MicroMIPSELSysVSetsockopt",
    "MicroMIPSELSysVShutdown",
    "MicroMIPSELSysVSocket",
    "MicroMIPSELSysVSocketpair",
]
