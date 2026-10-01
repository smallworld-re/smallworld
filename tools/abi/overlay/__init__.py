"""The committed, hand-curated overlay of the build-time ABI generator.

Everything here is source; nothing here is generated. The generated tables
(``smallworld/platforms/abi/_data``) are never committed: every build
regenerates them from the pinned dependencies plus this overlay.
"""

import typing

from . import authority, rules, versions, x86
from .schema import RecordSpec

#: Every record the tables ship, in table order.
#:
#: Table features. Each record names the feature it provides
#: (``RecordSpec.feature``): ``<architecture>-<variant>`` in lower-case
#: kebab form, e.g. ``x86-64-sysv`` for ``X86_64/LITTLE:sysv`` (the byte
#: order is added, ``-be``, only where a platform has both). The generated
#: ``_data`` package declares them, sorted, in ``FEATURES``, which
#: ``smallworld.platforms.abi.table_features()`` reports, so a consumer can
#: check for the records it needs (``{"x86-64-sysv"} <= table_features()``).
#: A build without tables declares none.
RECORDS: typing.Tuple[RecordSpec, ...] = (x86.X86_64_SYSV,)

#: The most master-seed markers the overlay may carry. Each PR that converts
#: markers into real citations lowers it; stage 2 fails when the overlay
#: exceeds it.
MASTER_SEED_CEILING = 24

__all__ = ["MASTER_SEED_CEILING", "RECORDS", "authority", "rules", "versions"]
