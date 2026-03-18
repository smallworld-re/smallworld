import logging
import typing

from ...filedesc import BasicIO, BytesIO, FDIOClosed, FDIOUnsupported
from .sockaddr import Sockaddr

logger = logging.getLogger(__name__)


class SocketIO(BasicIO):
    """Model of a socket"""

    def __init__(
        self,
        name: str,
        domain: int,
        type: int,
        protocol: int,
        interactive: bool,
        **kwargs,
    ):
        super().__init__(name, interactive, interactive, False, False, False, **kwargs)

        self.domain = domain
        self.type = type
        self.protocol = protocol

        self.peername: typing.Optional[Sockaddr] = None
        self.sockname: typing.Optional[Sockaddr] = None

    def on_recv(self) -> typing.Tuple[bytes, Sockaddr]:
        raise FDIOUnsupported("Socket does not support receiving")

    def on_send(self, data: bytes, peername: Sockaddr):
        data_str = " ".join(map(lambda x: f"{x:02x}", data))
        logger.info(f"Sending {data_str} to {peername}")

    def recv(self, peek: bool) -> typing.Tuple[bytes, Sockaddr]:
        if self._closed:
            raise FDIOClosed("Socket is closed")

        if not self._readable:
            raise FDIOUnsupported("Socket does not support receiving")

        return self.on_recv()

    def send(self, data: bytes, peername: Sockaddr) -> None:
        if self._closed:
            raise FDIOClosed("Socket is closed")

        if not self._writable:
            raise FDIOUnsupported("Socket does not support sending")

        return self.on_send(data, peername)


class BytesSocketIO(SocketIO, BytesIO):
    pass


__all__ = ["SocketIO"]
