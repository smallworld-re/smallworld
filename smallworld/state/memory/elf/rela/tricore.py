from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator


class TriCoreElfRelocator(ElfRelocator):
    arch = platforms.Architecture.TRICORE
    byteorder = platforms.Byteorder.LITTLE

    def _compute_value(self, rela: ElfRela, elf):
        raise ConfigurationError(
            f"Unknown relocation type for {rela.symbol.name}: {rela.type}"
        )
