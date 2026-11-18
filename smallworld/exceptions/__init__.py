from .exceptions import *  # noqa: F401, F403
from .exceptions import __all__ as __exceptions__
from .unstable import *  # noqa: F401, F403

# The `from .unstable import *` above pulls these into the package namespace
# (e.g. analyses.colorizer imports AnalysisRunError from here); include them in
# __all__ so `from smallworld.exceptions import *` re-exports them too.
__all__ = __exceptions__ + [  # noqa: F405
    "UnicornEmulationError",
    "AnalysisSetupError",
    "AnalysisRunError",
    "AnalysisSignal",
]
