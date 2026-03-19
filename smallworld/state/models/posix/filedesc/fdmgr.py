import io
import logging
import typing

from .....exceptions import ConfigurationError
from .....platforms import Architecture, Byteorder
from ...filedesc import FDIOInvalid, FDIOUnsupported, FileDescriptorManager
from .sockaddr import Sockaddr
from .socket import BytesSocketIO, SocketIO

logger = logging.getLogger(__name__)


class POSIXFileDescriptorManager(FileDescriptorManager):
    # Socket domain/type/protocol constants.
    # These are not consistent across platforms

    AF_UNIX = 1
    """Socket domain: UNIX sockets"""

    AF_INET = 2
    """Socket domain: IPv4"""

    AF_INET6 = 10
    """Socket domain: IPv6"""

    @property
    def SOCK_STREAM(self) -> int:
        """Socket type: Stream socket"""
        # Of course it's MIPS.
        if self.platform.architecture in (Architecture.MIPS32, Architecture.MIPS64):
            return 2
        else:
            return 1

    @property
    def SOCK_DGRAM(self) -> int:
        """Socket type: Datagram socket"""
        # Of course it's MIPS.
        if self.platform.architecture in (Architecture.MIPS32, Architecture.MIPS64):
            return 1
        else:
            return 2

    PROTO_DEFAULT = 0
    """Socket protocol: Default"""

    PROTO_TCP = 6
    """Socket protocol: TCP"""

    PROTO_UDP = 17
    """Socket protocol: UDP"""

    @property
    def SOCKET_CONFIGS(self) -> typing.List[typing.Tuple[int, int, int]]:
        return [
            (self.AF_UNIX, self.SOCK_STREAM, self.PROTO_DEFAULT),  # Unix stream
            (self.AF_UNIX, self.SOCK_DGRAM, self.PROTO_DEFAULT),  # Unix datagram
            (
                self.AF_INET,
                self.SOCK_STREAM,
                self.PROTO_DEFAULT,
            ),  # tcp/ip (default encoding)
            (self.AF_INET, self.SOCK_STREAM, self.PROTO_TCP),  # tcp/ip
            (
                self.AF_INET,
                self.SOCK_DGRAM,
                self.PROTO_DEFAULT,
            ),  # udp/ip (default encoding)
            (self.AF_INET, self.SOCK_DGRAM, self.PROTO_UDP),  # udp/ip
            (
                self.AF_INET6,
                self.SOCK_STREAM,
                self.PROTO_DEFAULT,
            ),  # tcp/ip6 (default encoding)
            (self.AF_INET6, self.SOCK_STREAM, self.PROTO_TCP),  # tcp/ip6
            (
                self.AF_INET6,
                self.SOCK_DGRAM,
                self.PROTO_DEFAULT,
            ),  # udp/ip6 (default encoding)
            (self.AF_INET6, self.SOCK_DGRAM, self.PROTO_UDP),  # udp/ip6
        ]

    def __init__(self):
        super().__init__()

        self._inbound: typing.Dict[
            typing.Tuple[int, int, int, Sockaddr], typing.List[SocketIO]
        ] = dict()

    def add_connection(
        self,
        domain: int,
        type: int,
        protocol: int,
        sockname: Sockaddr,
        peername: Sockaddr,
        data: bytes,
    ):
        if (domain, type, protocol) not in self.SOCKET_CONFIGS:
            raise ConfigurationError(
                "Unknown domain/type/protocol {domain}, {type}, {protocol}"
            )

        backing = io.BytesIO(data)
        connsock = BytesSocketIO("Socket", domain, type, protocol, True, data=backing)
        connsock.peername = peername

        queue = self._inbound.setdefault((domain, type, protocol, sockname), list())
        queue.append(connsock)

    def accept(self, fd: int) -> typing.Tuple[int, SocketIO]:
        socket = self.get_fd(fd)

        if not isinstance(socket, SocketIO):
            raise FDIOInvalid(f"{fd} is not a socket")

        if socket.sockname is None:
            raise FDIOInvalid(f"{fd} is not bound")

        if (
            socket.domain,
            socket.type,
            socket.protocol,
            socket.sockname,
        ) not in self._inbound:
            raise ConfigurationError(
                f"Attempted to accept on {socket.domain}, {socket.type}, {socket.protocol}, {socket.sockname}, but no inbound connections provided: {self._inbound}"
            )

        if (
            len(
                self._inbound[
                    (socket.domain, socket.type, socket.protocol, socket.sockname)
                ]
            )
            == 0
        ):
            raise ConfigurationError(
                f"Attempted to accept on {socket.domain}, {socket.type}, {socket.protocol}, {socket.sockname}, but no inbound connections are available"
            )

        connsock = self._inbound[
            (socket.domain, socket.type, socket.protocol, socket.sockname)
        ].pop(0)
        logger.debug(
            f"Accepted connection from {connsock.peername} to {socket.sockname}"
        )

        connfd = self._get_free_fd()
        self._fds[connfd] = connsock

        return (connfd, connsock)

    def bind(self, fd: int, addr_bytes: bytes) -> None:
        socket = self.get_fd(fd)

        if not isinstance(socket, SocketIO):
            raise FDIOInvalid(f"{fd} is not a socket")

        byteorder: typing.Literal["big", "little"]
        if self.platform.byteorder == Byteorder.BIG:
            byteorder = "big"
        else:
            byteorder = "little"

        sockname = Sockaddr.for_family(socket.domain)
        sockname.from_bytes(addr_bytes, byteorder)

        socket.sockname = sockname

        logger.debug(f"Bound {fd} to {sockname}")

    def connect(self, fd: int, addr_bytes: bytes) -> None:
        socket = self.get_fd(fd)

        if not isinstance(socket, SocketIO):
            raise FDIOInvalid(f"{fd} is not a socket")

        byteorder: typing.Literal["big", "little"]
        if self.platform.byteorder == Byteorder.BIG:
            byteorder = "big"
        else:
            byteorder = "little"

        peername = Sockaddr.for_family(socket.domain)
        peername.from_bytes(addr_bytes, byteorder)

        socket.peername = peername

        logger.debug(f"Connected {fd} to {peername}")

    def socket(self, domain: int, type: int, protocol: int) -> int:
        fd = self._get_free_fd()

        if (domain, type, protocol) not in self.SOCKET_CONFIGS:
            raise FDIOUnsupported(
                f"Unknown domain/type/protocol: {domain}, {type}, {protocol}"
            )

        interactive = type == self.SOCK_DGRAM

        socket = SocketIO("Socket", domain, type, protocol, interactive)
        self._fds[fd] = socket

        return fd


__all__ = ["POSIXFileDescriptorManager"]
