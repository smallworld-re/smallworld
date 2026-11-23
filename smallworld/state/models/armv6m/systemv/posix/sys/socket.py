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
from ...systemv import ArmV6MSysVModel


class ArmV6MSysVAccept(Accept, ArmV6MSysVModel):
    pass


class ArmV6MSysVBind(Bind, ArmV6MSysVModel):
    pass


class ArmV6MSysVConnect(Connect, ArmV6MSysVModel):
    pass


class ArmV6MSysVGetpeername(Getpeername, ArmV6MSysVModel):
    pass


class ArmV6MSysVGetsockname(Getsockname, ArmV6MSysVModel):
    pass


class ArmV6MSysVGetsockopt(Getsockopt, ArmV6MSysVModel):
    pass


class ArmV6MSysVListen(Listen, ArmV6MSysVModel):
    pass


class ArmV6MSysVRecv(Recv, ArmV6MSysVModel):
    pass


class ArmV6MSysVRecvfrom(Recvfrom, ArmV6MSysVModel):
    pass


class ArmV6MSysVRecvmsg(Recvmsg, ArmV6MSysVModel):
    pass


class ArmV6MSysVSend(Send, ArmV6MSysVModel):
    pass


class ArmV6MSysVSendmsg(Sendmsg, ArmV6MSysVModel):
    pass


class ArmV6MSysVSendto(Sendto, ArmV6MSysVModel):
    pass


class ArmV6MSysVSetsockopt(Setsockopt, ArmV6MSysVModel):
    pass


class ArmV6MSysVShutdown(Shutdown, ArmV6MSysVModel):
    pass


class ArmV6MSysVSocket(Socket, ArmV6MSysVModel):
    pass


class ArmV6MSysVSocketpair(Socketpair, ArmV6MSysVModel):
    pass


__all__ = [
    "ArmV6MSysVAccept",
    "ArmV6MSysVBind",
    "ArmV6MSysVConnect",
    "ArmV6MSysVGetpeername",
    "ArmV6MSysVGetsockname",
    "ArmV6MSysVGetsockopt",
    "ArmV6MSysVListen",
    "ArmV6MSysVRecv",
    "ArmV6MSysVRecvfrom",
    "ArmV6MSysVRecvmsg",
    "ArmV6MSysVSend",
    "ArmV6MSysVSendmsg",
    "ArmV6MSysVSendto",
    "ArmV6MSysVSetsockopt",
    "ArmV6MSysVShutdown",
    "ArmV6MSysVSocket",
    "ArmV6MSysVSocketpair",
]
