from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator


class TriCoreElfRelocator(ElfRelocator):
    supported_platforms = frozenset(
        {platforms.Platform(platforms.Architecture.TRICORE, platforms.Byteorder.LITTLE)}
    )

    def _compute_value(self, rela: ElfRela, elf):
        raise ConfigurationError(
            f"Unknown relocation type for {rela.symbol.name}: {rela.type}"
        )
