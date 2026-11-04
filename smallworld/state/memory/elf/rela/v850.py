from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator


class V850ElfRelocator(ElfRelocator):
    supported_platforms = frozenset(
        {platforms.Platform(platforms.Architecture.V850, platforms.Byteorder.LITTLE)}
    )

    def _compute_value(self, rela: ElfRela, elf):
        raise ConfigurationError(
            f"Unknown relocation type for {rela.symbol.name}: {rela.type}"
        )
