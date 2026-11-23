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
from ...systemv import ArmV5TBESysVModel


class ArmV5TBESysVAccept(Accept, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVBind(Bind, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVConnect(Connect, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVGetpeername(Getpeername, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVGetsockname(Getsockname, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVGetsockopt(Getsockopt, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVListen(Listen, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVRecv(Recv, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVRecvfrom(Recvfrom, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVRecvmsg(Recvmsg, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSend(Send, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSendmsg(Sendmsg, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSendto(Sendto, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSetsockopt(Setsockopt, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVShutdown(Shutdown, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSocket(Socket, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSocketpair(Socketpair, ArmV5TBESysVModel):
    pass


__all__ = [
    "ArmV5TBESysVAccept",
    "ArmV5TBESysVBind",
    "ArmV5TBESysVConnect",
    "ArmV5TBESysVGetpeername",
    "ArmV5TBESysVGetsockname",
    "ArmV5TBESysVGetsockopt",
    "ArmV5TBESysVListen",
    "ArmV5TBESysVRecv",
    "ArmV5TBESysVRecvfrom",
    "ArmV5TBESysVRecvmsg",
    "ArmV5TBESysVSend",
    "ArmV5TBESysVSendmsg",
    "ArmV5TBESysVSendto",
    "ArmV5TBESysVSetsockopt",
    "ArmV5TBESysVShutdown",
    "ArmV5TBESysVSocket",
    "ArmV5TBESysVSocketpair",
]
