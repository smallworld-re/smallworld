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
from ...systemv import ArmV6KSysVModel


class ArmV6KSysVAccept(Accept, ArmV6KSysVModel):
    pass


class ArmV6KSysVBind(Bind, ArmV6KSysVModel):
    pass


class ArmV6KSysVConnect(Connect, ArmV6KSysVModel):
    pass


class ArmV6KSysVGetpeername(Getpeername, ArmV6KSysVModel):
    pass


class ArmV6KSysVGetsockname(Getsockname, ArmV6KSysVModel):
    pass


class ArmV6KSysVGetsockopt(Getsockopt, ArmV6KSysVModel):
    pass


class ArmV6KSysVListen(Listen, ArmV6KSysVModel):
    pass


class ArmV6KSysVRecv(Recv, ArmV6KSysVModel):
    pass


class ArmV6KSysVRecvfrom(Recvfrom, ArmV6KSysVModel):
    pass


class ArmV6KSysVRecvmsg(Recvmsg, ArmV6KSysVModel):
    pass


class ArmV6KSysVSend(Send, ArmV6KSysVModel):
    pass


class ArmV6KSysVSendmsg(Sendmsg, ArmV6KSysVModel):
    pass


class ArmV6KSysVSendto(Sendto, ArmV6KSysVModel):
    pass


class ArmV6KSysVSetsockopt(Setsockopt, ArmV6KSysVModel):
    pass


class ArmV6KSysVShutdown(Shutdown, ArmV6KSysVModel):
    pass


class ArmV6KSysVSocket(Socket, ArmV6KSysVModel):
    pass


class ArmV6KSysVSocketpair(Socketpair, ArmV6KSysVModel):
    pass


__all__ = [
    "ArmV6KSysVAccept",
    "ArmV6KSysVBind",
    "ArmV6KSysVConnect",
    "ArmV6KSysVGetpeername",
    "ArmV6KSysVGetsockname",
    "ArmV6KSysVGetsockopt",
    "ArmV6KSysVListen",
    "ArmV6KSysVRecv",
    "ArmV6KSysVRecvfrom",
    "ArmV6KSysVRecvmsg",
    "ArmV6KSysVSend",
    "ArmV6KSysVSendmsg",
    "ArmV6KSysVSendto",
    "ArmV6KSysVSetsockopt",
    "ArmV6KSysVShutdown",
    "ArmV6KSysVSocket",
    "ArmV6KSysVSocketpair",
]
