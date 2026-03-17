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
from ...systemv import ArmHFSysVModel


class ArmHFSysVAccept(Accept, ArmHFSysVModel):
    pass


class ArmHFSysVBind(Bind, ArmHFSysVModel):
    pass


class ArmHFSysVConnect(Connect, ArmHFSysVModel):
    pass


class ArmHFSysVGetpeername(Getpeername, ArmHFSysVModel):
    pass


class ArmHFSysVGetsockname(Getsockname, ArmHFSysVModel):
    pass


class ArmHFSysVGetsockopt(Getsockopt, ArmHFSysVModel):
    pass


class ArmHFSysVListen(Listen, ArmHFSysVModel):
    pass


class ArmHFSysVRecv(Recv, ArmHFSysVModel):
    pass


class ArmHFSysVRecvfrom(Recvfrom, ArmHFSysVModel):
    pass


class ArmHFSysVRecvmsg(Recvmsg, ArmHFSysVModel):
    pass


class ArmHFSysVSend(Send, ArmHFSysVModel):
    pass


class ArmHFSysVSendmsg(Sendmsg, ArmHFSysVModel):
    pass


class ArmHFSysVSendto(Sendto, ArmHFSysVModel):
    pass


class ArmHFSysVSetsockopt(Setsockopt, ArmHFSysVModel):
    pass


class ArmHFSysVShutdown(Shutdown, ArmHFSysVModel):
    pass


class ArmHFSysVSocket(Socket, ArmHFSysVModel):
    pass


class ArmHFSysVSocketpair(Socketpair, ArmHFSysVModel):
    pass


__all__ = [
    "ArmHFSysVAccept",
    "ArmHFSysVBind",
    "ArmHFSysVConnect",
    "ArmHFSysVGetpeername",
    "ArmHFSysVGetsockname",
    "ArmHFSysVGetsockopt",
    "ArmHFSysVListen",
    "ArmHFSysVRecv",
    "ArmHFSysVRecvfrom",
    "ArmHFSysVRecvmsg",
    "ArmHFSysVSend",
    "ArmHFSysVSendmsg",
    "ArmHFSysVSendto",
    "ArmHFSysVSetsockopt",
    "ArmHFSysVShutdown",
    "ArmHFSysVSocket",
    "ArmHFSysVSocketpair",
]
