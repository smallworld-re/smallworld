import logging
import typing

from .....exceptions import ConfigurationError
from .....platforms import Platform
from ....cpus import CPU
from ..elf import ElfExecutable
from .prstatus import PrStatus

log = logging.getLogger(__name__)


ET_CORE = 4


class ElfCoreFile(ElfExecutable):
    """
    Extended loader to handle core-dump (ET_CORE) ELF files.
    """

    def __init__(
        self,
        file: typing.BinaryIO,
        platform: typing.Optional[Platform] = None,
        ignore_platform: bool = False,
        user_base: typing.Optional[int] = None,
        page_size: int = 0x1000,
    ):
        super().__init__(
            file=file,
            platform=platform,
            ignore_platform=ignore_platform,
            user_base=user_base,
            page_size=page_size,
        )

        assert self._elf is not None
        parsed_elf = self._elf

        if parsed_elf is None or parsed_elf.header.file_type.value != ET_CORE:
            raise ConfigurationError("This file is not an ELF core dump (ET_CORE).")

        assert self.platform is not None
        self.prstatus = PrStatus.for_platform(self.platform, parsed_elf)

    def populate_cpu(self, cpu: CPU) -> None:
        self.prstatus.populate_cpu(cpu)
