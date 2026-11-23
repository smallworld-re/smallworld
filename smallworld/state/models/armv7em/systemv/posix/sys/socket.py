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
from ...systemv import ArmV7EMSysVModel


class ArmV7EMSysVAccept(Accept, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVBind(Bind, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVConnect(Connect, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVGetpeername(Getpeername, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVGetsockname(Getsockname, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVGetsockopt(Getsockopt, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVListen(Listen, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVRecv(Recv, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVRecvfrom(Recvfrom, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVRecvmsg(Recvmsg, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSend(Send, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSendmsg(Sendmsg, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSendto(Sendto, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSetsockopt(Setsockopt, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVShutdown(Shutdown, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSocket(Socket, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSocketpair(Socketpair, ArmV7EMSysVModel):
    pass


__all__ = [
    "ArmV7EMSysVAccept",
    "ArmV7EMSysVBind",
    "ArmV7EMSysVConnect",
    "ArmV7EMSysVGetpeername",
    "ArmV7EMSysVGetsockname",
    "ArmV7EMSysVGetsockopt",
    "ArmV7EMSysVListen",
    "ArmV7EMSysVRecv",
    "ArmV7EMSysVRecvfrom",
    "ArmV7EMSysVRecvmsg",
    "ArmV7EMSysVSend",
    "ArmV7EMSysVSendmsg",
    "ArmV7EMSysVSendto",
    "ArmV7EMSysVSetsockopt",
    "ArmV7EMSysVShutdown",
    "ArmV7EMSysVSocket",
    "ArmV7EMSysVSocketpair",
]
