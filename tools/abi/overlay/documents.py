"""The documents the overlay cites, each named one way."""

from .schema import Cite

#: The AMD64 psABI, by the title on its cover page.
AMD64_PSABI = (
    "System V Application Binary Interface, AMD64 Architecture Processor Supplement"
)
AMD64_PSABI_VERSION = "1.0"


def amd64_psabi(section: str) -> Cite:
    """A section of the AMD64 psABI."""
    return Cite.psabi(AMD64_PSABI, AMD64_PSABI_VERSION, section)


#: glibc, at the tag its line numbers are for.
GLIBC_TAG = "glibc-2.39"

#: The Linux man-pages release whose syscall(2) tables are cited.
MAN_PAGES = "man-pages 6.7"
