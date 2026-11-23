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
from ...systemv import ArmV7MSysVModel


class ArmV7MSysVAccept(Accept, ArmV7MSysVModel):
    pass


class ArmV7MSysVBind(Bind, ArmV7MSysVModel):
    pass


class ArmV7MSysVConnect(Connect, ArmV7MSysVModel):
    pass


class ArmV7MSysVGetpeername(Getpeername, ArmV7MSysVModel):
    pass


class ArmV7MSysVGetsockname(Getsockname, ArmV7MSysVModel):
    pass


class ArmV7MSysVGetsockopt(Getsockopt, ArmV7MSysVModel):
    pass


class ArmV7MSysVListen(Listen, ArmV7MSysVModel):
    pass


class ArmV7MSysVRecv(Recv, ArmV7MSysVModel):
    pass


class ArmV7MSysVRecvfrom(Recvfrom, ArmV7MSysVModel):
    pass


class ArmV7MSysVRecvmsg(Recvmsg, ArmV7MSysVModel):
    pass


class ArmV7MSysVSend(Send, ArmV7MSysVModel):
    pass


class ArmV7MSysVSendmsg(Sendmsg, ArmV7MSysVModel):
    pass


class ArmV7MSysVSendto(Sendto, ArmV7MSysVModel):
    pass


class ArmV7MSysVSetsockopt(Setsockopt, ArmV7MSysVModel):
    pass


class ArmV7MSysVShutdown(Shutdown, ArmV7MSysVModel):
    pass


class ArmV7MSysVSocket(Socket, ArmV7MSysVModel):
    pass


class ArmV7MSysVSocketpair(Socketpair, ArmV7MSysVModel):
    pass


__all__ = [
    "ArmV7MSysVAccept",
    "ArmV7MSysVBind",
    "ArmV7MSysVConnect",
    "ArmV7MSysVGetpeername",
    "ArmV7MSysVGetsockname",
    "ArmV7MSysVGetsockopt",
    "ArmV7MSysVListen",
    "ArmV7MSysVRecv",
    "ArmV7MSysVRecvfrom",
    "ArmV7MSysVRecvmsg",
    "ArmV7MSysVSend",
    "ArmV7MSysVSendmsg",
    "ArmV7MSysVSendto",
    "ArmV7MSysVSetsockopt",
    "ArmV7MSysVShutdown",
    "ArmV7MSysVSocket",
    "ArmV7MSysVSocketpair",
]
