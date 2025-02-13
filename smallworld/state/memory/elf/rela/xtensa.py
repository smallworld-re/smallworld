from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator


class XtensaElfRelocator(ElfRelocator):
    arch = platforms.Architecture.XTENSA
    byteorder = platforms.Byteorder.LITTLE

    def _compute_value(self, rela: ElfRela):
        # Xtensa doesn't have a dynamic linker.
        raise ConfigurationError(
            "Unknown relocation type for {rela.symbol.name}: {rela.type}"
        )
