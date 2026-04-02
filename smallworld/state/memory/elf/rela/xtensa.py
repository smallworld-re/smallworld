from ..... import platforms
from .....exceptions import ConfigurationError
from ..structs import ElfRela
from .rela import ElfRelocator

# Xtensa ELF support in SmallWorld currently models no processor-specific
# relocation formulas here. This relocator is an explicit fail-fast so a harness
# author sees the unsupported relocation rather than silently receiving a wrong
# value.


class XtensaElfRelocator(ElfRelocator):
    arch = platforms.Architecture.XTENSA
    byteorder = platforms.Byteorder.LITTLE

    def _compute_value(self, rela: ElfRela, elf):
        # Xtensa doesn't have a dynamic linker.
        raise ConfigurationError(
            f"Unknown relocation type for {rela.symbol.name}: {rela.type}"
        )
