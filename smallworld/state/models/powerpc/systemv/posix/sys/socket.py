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
from ...systemv import PowerPCSysVModel


class PowerPCSysVAccept(Accept, PowerPCSysVModel):
    pass


class PowerPCSysVBind(Bind, PowerPCSysVModel):
    pass


class PowerPCSysVConnect(Connect, PowerPCSysVModel):
    pass


class PowerPCSysVGetpeername(Getpeername, PowerPCSysVModel):
    pass


class PowerPCSysVGetsockname(Getsockname, PowerPCSysVModel):
    pass


class PowerPCSysVGetsockopt(Getsockopt, PowerPCSysVModel):
    pass


class PowerPCSysVListen(Listen, PowerPCSysVModel):
    pass


class PowerPCSysVRecv(Recv, PowerPCSysVModel):
    pass


class PowerPCSysVRecvfrom(Recvfrom, PowerPCSysVModel):
    pass


class PowerPCSysVRecvmsg(Recvmsg, PowerPCSysVModel):
    pass


class PowerPCSysVSend(Send, PowerPCSysVModel):
    pass


class PowerPCSysVSendmsg(Sendmsg, PowerPCSysVModel):
    pass


class PowerPCSysVSendto(Sendto, PowerPCSysVModel):
    pass


class PowerPCSysVSetsockopt(Setsockopt, PowerPCSysVModel):
    pass


class PowerPCSysVShutdown(Shutdown, PowerPCSysVModel):
    pass


class PowerPCSysVSocket(Socket, PowerPCSysVModel):
    pass


class PowerPCSysVSocketpair(Socketpair, PowerPCSysVModel):
    pass


__all__ = [
    "PowerPCSysVAccept",
    "PowerPCSysVBind",
    "PowerPCSysVConnect",
    "PowerPCSysVGetpeername",
    "PowerPCSysVGetsockname",
    "PowerPCSysVGetsockopt",
    "PowerPCSysVListen",
    "PowerPCSysVRecv",
    "PowerPCSysVRecvfrom",
    "PowerPCSysVRecvmsg",
    "PowerPCSysVSend",
    "PowerPCSysVSendmsg",
    "PowerPCSysVSendto",
    "PowerPCSysVSetsockopt",
    "PowerPCSysVShutdown",
    "PowerPCSysVSocket",
    "PowerPCSysVSocketpair",
]
