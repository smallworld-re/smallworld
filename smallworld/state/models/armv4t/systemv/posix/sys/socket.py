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
from ...systemv import ArmV4TSysVModel


class ArmV4TSysVAccept(Accept, ArmV4TSysVModel):
    pass


class ArmV4TSysVBind(Bind, ArmV4TSysVModel):
    pass


class ArmV4TSysVConnect(Connect, ArmV4TSysVModel):
    pass


class ArmV4TSysVGetpeername(Getpeername, ArmV4TSysVModel):
    pass


class ArmV4TSysVGetsockname(Getsockname, ArmV4TSysVModel):
    pass


class ArmV4TSysVGetsockopt(Getsockopt, ArmV4TSysVModel):
    pass


class ArmV4TSysVListen(Listen, ArmV4TSysVModel):
    pass


class ArmV4TSysVRecv(Recv, ArmV4TSysVModel):
    pass


class ArmV4TSysVRecvfrom(Recvfrom, ArmV4TSysVModel):
    pass


class ArmV4TSysVRecvmsg(Recvmsg, ArmV4TSysVModel):
    pass


class ArmV4TSysVSend(Send, ArmV4TSysVModel):
    pass


class ArmV4TSysVSendmsg(Sendmsg, ArmV4TSysVModel):
    pass


class ArmV4TSysVSendto(Sendto, ArmV4TSysVModel):
    pass


class ArmV4TSysVSetsockopt(Setsockopt, ArmV4TSysVModel):
    pass


class ArmV4TSysVShutdown(Shutdown, ArmV4TSysVModel):
    pass


class ArmV4TSysVSocket(Socket, ArmV4TSysVModel):
    pass


class ArmV4TSysVSocketpair(Socketpair, ArmV4TSysVModel):
    pass


__all__ = [
    "ArmV4TSysVAccept",
    "ArmV4TSysVBind",
    "ArmV4TSysVConnect",
    "ArmV4TSysVGetpeername",
    "ArmV4TSysVGetsockname",
    "ArmV4TSysVGetsockopt",
    "ArmV4TSysVListen",
    "ArmV4TSysVRecv",
    "ArmV4TSysVRecvfrom",
    "ArmV4TSysVRecvmsg",
    "ArmV4TSysVSend",
    "ArmV4TSysVSendmsg",
    "ArmV4TSysVSendto",
    "ArmV4TSysVSetsockopt",
    "ArmV4TSysVShutdown",
    "ArmV4TSysVSocket",
    "ArmV4TSysVSocketpair",
]
