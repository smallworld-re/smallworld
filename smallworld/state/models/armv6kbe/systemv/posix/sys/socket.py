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
from ...systemv import ArmV6KBESysVModel


class ArmV6KBESysVAccept(Accept, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVBind(Bind, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVConnect(Connect, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVGetpeername(Getpeername, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVGetsockname(Getsockname, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVGetsockopt(Getsockopt, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVListen(Listen, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVRecv(Recv, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVRecvfrom(Recvfrom, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVRecvmsg(Recvmsg, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSend(Send, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSendmsg(Sendmsg, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSendto(Sendto, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSetsockopt(Setsockopt, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVShutdown(Shutdown, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSocket(Socket, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSocketpair(Socketpair, ArmV6KBESysVModel):
    pass


__all__ = [
    "ArmV6KBESysVAccept",
    "ArmV6KBESysVBind",
    "ArmV6KBESysVConnect",
    "ArmV6KBESysVGetpeername",
    "ArmV6KBESysVGetsockname",
    "ArmV6KBESysVGetsockopt",
    "ArmV6KBESysVListen",
    "ArmV6KBESysVRecv",
    "ArmV6KBESysVRecvfrom",
    "ArmV6KBESysVRecvmsg",
    "ArmV6KBESysVSend",
    "ArmV6KBESysVSendmsg",
    "ArmV6KBESysVSendto",
    "ArmV6KBESysVSetsockopt",
    "ArmV6KBESysVShutdown",
    "ArmV6KBESysVSocket",
    "ArmV6KBESysVSocketpair",
]
