"""The ABI record registry and lookups.

Records come from a data module, :data:`DATA_MODULE`, that exposes
``RECORDS: Tuple[ABIDef, ...]`` built from plain constructor calls over
literals. That module is generated when smallworld is built or installed and
is not part of the source tree, so it may be absent.

The tables are loaded eagerly, exactly once: this module imports
:data:`DATA_MODULE` when it is itself imported, which happens whenever
:mod:`smallworld.platforms.abi` is imported. ``import smallworld`` does not
import this package, so it loads no tables. Importing never raises because
of the tables. If the data module is missing, fails to import, is malformed,
or is a no-data marker (``AVAILABLE = False``), the reason is recorded as
text (with the formatted traceback when the import raised), and every
lookup -- including :func:`maybe_resolve` and the listing functions --
raises :class:`~smallworld.platforms.abi.errors.ABITablesUnavailable` with
it, so a missing install step is never mistaken for "not modelled". That is
the case in builds that did not generate tables: source checkouts, and
Python 3.9 and 3.11 builds. :func:`tables_available` and
:func:`table_features` describe the tables without raising.

The load is not retried, so tables installed while the process runs are not
picked up. At import the loader checks only the structure lookups rely on:
``RECORDS`` is a tuple of :class:`ABIDef` with unique ids and keys and at
most one default per platform and per family, and ``FEATURES`` is a tuple of
strings. It does not run :func:`~smallworld.platforms.abi.validate.check_records`;
the generator and CI do, which keeps the import cheap.

The data module is imported while :mod:`smallworld.platforms.abi` is still
initializing, after its ``enums``, ``errors``, ``model`` and ``validate``
names are bound but before this module's lookups are. It may import
:mod:`smallworld.platforms` and those names, but must not look anything up.
"""

import contextlib
import importlib
import os
import sys
import traceback
import typing
import warnings

from ..platforms import ABI, Platform
from .errors import ABITablesStale, ABITablesUnavailable
from .model import ABIDef

#: The module the tables are loaded from. It must define ``RECORDS``, a tuple
#: of :class:`ABIDef`, and may define ``FEATURES``, a tuple of the table
#: feature names it provides (see :func:`table_features`). A data module
#: written for a build without tables sets ``AVAILABLE`` to ``False`` and
#: ``REASON`` to a sentence saying why, and needs neither; lookups then raise
#: with that reason. ``AVAILABLE`` defaults to ``True``. Tables an editable
#: build kept although their inputs changed carry ``STALE``, a sentence saying
#: why; loading them warns with :class:`ABITablesStale`. The name is derived
#: from this module's own package (``smallworld.platforms.abi._data``), so a
#: copy of the package imported under another name (the build-time
#: generator loads one) reads its own data module, never the installed one.
DATA_MODULE = __name__.rpartition(".")[0] + "._data"

#: Values accepted by ``default_variant(container=...)`` and the ABI family
#: that is the default for that container (``None``: the platform default).
_CONTAINER_FAMILY: typing.Dict[str, typing.Optional[ABI]] = {
    "elf": None,
    "pe": ABI.WINDOWS,
}


class _Registry:
    """An immutable index over one record set."""

    def __init__(
        self,
        records: typing.Iterable[ABIDef],
        source: str,
        features: typing.Iterable[str] = (),
    ) -> None:
        self.source = source
        self.features: typing.FrozenSet[str] = frozenset(features)
        self.records: typing.Tuple[ABIDef, ...] = tuple(records)
        self.by_id: typing.Dict[str, ABIDef] = {}
        self.by_key: typing.Dict[typing.Tuple[Platform, str], ABIDef] = {}
        self.default: typing.Dict[Platform, ABIDef] = {}
        self.family_default: typing.Dict[typing.Tuple[Platform, ABI], ABIDef] = {}
        self.variants: typing.Dict[Platform, typing.Tuple[str, ...]] = {}

        variants: typing.Dict[Platform, typing.List[str]] = {}
        for record in self.records:
            if not isinstance(record, ABIDef):
                raise TypeError(f"{source}: {record!r} is not an ABIDef")
            if record.id in self.by_id:
                raise ValueError(f"{source}: duplicate ABI record id {record.id!r}")
            if record.key in self.by_key:
                raise ValueError(
                    f"{source}: duplicate ABI record key {record.key!r} "
                    f"({self.by_key[record.key].id!r} and {record.id!r})"
                )
            self.by_id[record.id] = record
            self.by_key[record.key] = record
            variants.setdefault(record.platform, []).append(record.variant)
            if record.is_default:
                if record.platform in self.default:
                    raise ValueError(
                        f"{source}: two default ABI records for {record.platform}: "
                        f"{self.default[record.platform].id!r} and {record.id!r}"
                    )
                self.default[record.platform] = record
            if record.is_family_default:
                if record.abi is None:
                    raise ValueError(
                        f"{source}: {record.id!r} is a family default with no ABI family"
                    )
                family = (record.platform, record.abi)
                if family in self.family_default:
                    raise ValueError(
                        f"{source}: two {record.abi.name} family defaults for "
                        f"{record.platform}: {self.family_default[family].id!r} "
                        f"and {record.id!r}"
                    )
                self.family_default[family] = record
        self.variants = {p: tuple(v) for p, v in variants.items()}

    def lookup(
        self,
        platform: Platform,
        abi: typing.Optional[ABI],
        variant: typing.Optional[str],
    ) -> typing.Tuple[typing.Optional[ABIDef], str]:
        """The matching record, or ``None`` and the reason there is none."""
        if abi is not None and not isinstance(abi, ABI):
            raise TypeError(f"abi must be an ABI member or None, not {abi!r}")
        if variant is not None:
            record = self.by_key.get((platform, variant))
            if record is None:
                return None, f"no ABI record {variant!r} for {platform}"
            if abi is not None and record.abi != abi:
                family = (
                    f"the {record.abi.name} family"
                    if record.abi is not None
                    else "no ABI family"
                )
                return None, (
                    f"ABI record {record.id!r} belongs to {family}, "
                    f"not the {abi.name} family"
                )
            return record, ""
        if abi is None:
            record = self.default.get(platform)
            if record is None:
                return None, f"no default ABI record for {platform}"
            return record, ""
        record = self.family_default.get((platform, abi))
        if record is None:
            return None, f"no {abi.name} ABI record for {platform}"
        return record, ""


def _failure(summary: str, error: BaseException) -> str:
    """`summary`, followed by `error` and its cause chain formatted as
    ``traceback.format_exception`` prints them.

    Only this text is kept, so a failed load keeps no exception, traceback
    or frame alive.
    """
    detail = "".join(
        traceback.format_exception(type(error), error, error.__traceback__)
    ).rstrip()
    return f"{summary}:\n{detail}"


def _load_module(name: str) -> typing.Union[_Registry, str]:
    """The registry built from data module `name`, or why there is none.

    Raises whatever importing `name` raises, except that `name` itself not
    existing is reported as text.
    """
    try:
        module = importlib.import_module(name)
    except ModuleNotFoundError as e:
        if e.name != name:
            raise
        return (
            f"no ABI tables are installed ({name} does not exist); "
            "they are generated when smallworld is built or installed, and "
            "source checkouts and Python 3.9 and 3.11 builds have none. "
            "Rebuild with `pip install -e .`, `uv sync --reinstall-package "
            "smallworld-re`, or `python tools/abi/generate.py --inplace` in "
            "an environment with the build dependencies"
        )
    available = getattr(module, "AVAILABLE", True)
    if available is False:
        reason = getattr(module, "REASON", None)
        if not (isinstance(reason, str) and reason):
            reason = "no reason was recorded"
        return f"this installation has no ABI tables: {reason}"
    if available is not True:
        return f"{name}.AVAILABLE must be True or False, not {available!r}"
    records = getattr(module, "RECORDS", None)
    if not isinstance(records, tuple):
        return f"{name} does not define a RECORDS tuple"
    features = getattr(module, "FEATURES", ())
    if not (isinstance(features, tuple) and all(isinstance(f, str) for f in features)):
        return f"{name}.FEATURES must be a tuple of strings, not {features!r}"
    try:
        registry = _Registry(records, name, features)
    except (TypeError, ValueError) as e:
        return f"the ABI tables are invalid: {e}"
    global _stale_reason
    stale = getattr(module, "STALE", None)
    if isinstance(stale, str) and stale:
        message = f"the ABI tables in {name} are stale: {stale}"
        _stale_reason = message
        try:
            _warn_stale(message)
        except ABITablesStale:
            # The warning filter turned it into an error (python -W error).
            # Raising here would fail the import and lose the tables, which
            # are still usable, so they load; say so on stderr instead.
            sys.stderr.write(f"ABITablesStale (loaded anyway): {message}\n")
    else:
        _stale_reason = None
    return registry


#: Why the loaded tables are stale (their ``STALE`` note), or ``None``.
#: Private: set by the loader, read by tests and debugging.
_stale_reason: typing.Optional[str] = None


#: The directory of the smallworld package; frames inside it are not the
#: user's.
_SMALLWORLD_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)


#: The directory of the importlib package; its frames (importlib.import_module)
#: are not the user's either.
_IMPORTLIB_DIR = os.path.dirname(os.path.abspath(importlib.__file__))


def _internal(filename: str) -> bool:
    """A frame :mod:`warnings` does not count (the frozen import system)."""
    return "importlib" in filename and "_bootstrap" in filename


def _warn_stale(message: str) -> None:
    """Warn with :class:`ABITablesStale`, attributed to the first frame
    outside smallworld and the import machinery: the user's ``import``
    statement, ``importlib.import_module`` call or lookup, which is where
    Python shows the warning and where ``-W``, pytest and
    ``warnings.filterwarnings`` match it."""
    # warnings counts stack levels skipping the frozen import system's frames
    # (warnings._is_internal_frame), so count the same way. importlib-package
    # frames (importlib/__init__.py) are counted but walked past.
    level = 1
    frame = sys._getframe(1)
    while frame is not None:
        filename = frame.f_code.co_filename
        if not _internal(filename):
            level += 1
            path = os.path.abspath(filename)
            ours = path.startswith(_SMALLWORLD_DIR + os.sep) or path.startswith(
                _IMPORTLIB_DIR + os.sep
            )
            if not ours:
                break
        frame = frame.f_back  # type: ignore[assignment]
    warnings.warn(message, ABITablesStale, stacklevel=level)


def _load(name: str) -> typing.Union[_Registry, str]:
    """Like :func:`_load_module`, but never raises an :class:`Exception`:
    one raised while importing or indexing `name` is reported as text."""
    try:
        return _load_module(name)
    except Exception as e:
        return _failure(f"the ABI tables in {name} failed to load", e)


#: The registry built from :data:`DATA_MODULE`, or the text saying why there
#: is none. Set once, at the bottom of this module, when it is imported; this
#: placeholder is what a lookup made while the data module is being imported
#: sees.
_tables: typing.Union[_Registry, str] = (
    f"the ABI tables were looked up while {DATA_MODULE} was being imported"
)
#: A record set installed by _use_records(); takes precedence over _tables.
_override: typing.Optional[_Registry] = None


def _reload(name: typing.Optional[str] = None) -> None:
    """Run the loader again, against `name` or :data:`DATA_MODULE` (test hook).

    A module already in ``sys.modules`` is reused, not executed again; one
    that failed to import is not there, so it is imported afresh.
    """
    global _tables
    importlib.invalidate_caches()
    _tables = _load(DATA_MODULE if name is None else name)


def _data_registry() -> _Registry:
    """The registry built from the data module; raises if there is none."""
    tables = _tables
    if isinstance(tables, str):
        raise ABITablesUnavailable(tables)
    return tables


def _registry() -> _Registry:
    override = _override
    if override is not None:
        return override
    return _data_registry()


def tables_available() -> bool:
    """Whether the ABI tables in :data:`DATA_MODULE` loaded.

    Never raises. False in builds that did not generate tables: source
    checkouts, and Python 3.9 and 3.11 builds.
    """
    return not isinstance(_tables, str)


def table_features() -> typing.FrozenSet[str]:
    """The feature names the installed ABI tables provide.

    Read from the ``FEATURES`` tuple of :data:`DATA_MODULE`; ``frozenset()``
    when the module defines none or there are no tables. This describes the
    generated data; :data:`smallworld.platforms.abi.API_FEATURES` describes
    the code. Never raises.
    """
    tables = _tables
    if isinstance(tables, str):
        return frozenset()
    return tables.features


@contextlib.contextmanager
def _use_records(records: typing.Iterable[ABIDef]) -> typing.Iterator[None]:
    """Serve lookups from `records` inside the ``with`` block (test hook).

    The previous record set is restored on exit. Records looked up,
    unpickled or deep-copied inside the block resolve against `records`.
    :func:`tables_available` and :func:`table_features` still describe
    :data:`DATA_MODULE`, not `records`.
    """
    global _override
    registry = _Registry(records, "_use_records()")
    previous = _override
    _override = registry
    try:
        yield
    finally:
        _override = previous


def resolve(
    platform: Platform,
    abi: typing.Optional[ABI] = None,
    variant: typing.Optional[str] = None,
) -> ABIDef:
    """The ABI record for `platform`.

    * With `variant`: that record, whatever its family. If `abi` is also
      given, the record must belong to that family.
    * With only `abi`: that family's default record on `platform`.
    * With neither: the platform's default record, which is its SYSTEMV
      family default (:func:`~smallworld.platforms.abi.validate.check_records`
      enforces this). For a PE binary use ``resolve(platform, ABI.WINDOWS)``,
      the WINDOWS family default.

    Returns:
        The registry's record; the same object on every call.

    Raises:
        ValueError: If there is no such record, or `variant` is not in the
            family `abi`.
        TypeError: If `abi` is neither an :class:`~smallworld.platforms.ABI`
            nor ``None``.
        ABITablesUnavailable: If the ABI tables did not load when this
            package was imported, with the reason recorded then; for example
            none are installed, as in builds that did not generate tables:
            source checkouts, and Python 3.9 and 3.11 builds.
    """
    record, reason = _registry().lookup(platform, abi, variant)
    if record is None:
        raise ValueError(reason)
    return record


def maybe_resolve(
    platform: Platform,
    abi: typing.Optional[ABI] = None,
    variant: typing.Optional[str] = None,
) -> typing.Optional[ABIDef]:
    """Like :func:`resolve`, but ``None`` when there is no such record.

    ``None`` means "not modelled"; a record whose ``int_arg_registers()`` is
    ``()`` means "modelled, stack-only".

    Raises:
        ABITablesUnavailable: If the ABI tables did not load, rather than
            returning ``None``, so that a missing install step is not
            mistaken for "not modelled"; for example in builds that did not
            generate tables: source checkouts, and Python 3.9 and 3.11
            builds.
    """
    record, _ = _registry().lookup(platform, abi, variant)
    return record


def mechanics_for(platform: Platform, abi: typing.Optional[ABI]) -> ABIDef:
    """The record whose return mechanics a model with ABI `abi` uses.

    A model whose ABI has no record (``ABI.NONE``) still gets the platform's
    default record, so its hook can return.
    """
    return maybe_resolve(platform, abi) or resolve(platform)


def variants(platform: Platform) -> typing.Tuple[str, ...]:
    """The variant names defined for `platform`, in table order; ``()`` if
    there are none.

    Raises:
        ABITablesUnavailable: If the ABI tables did not load.
    """
    return _registry().variants.get(platform, ())


def default_variant(platform: Platform, container: str = "elf") -> str:
    """The default variant for `platform` in a binary of kind `container`.

    ``"elf"`` gives the platform default; ``"pe"`` the WINDOWS family
    default.

    Raises:
        ValueError: If `container` is unknown or there is no such record.
        ABITablesUnavailable: If the ABI tables did not load.
    """
    try:
        family = _CONTAINER_FAMILY[container]
    except KeyError:
        raise ValueError(
            f"unknown container {container!r}; use one of {sorted(_CONTAINER_FAMILY)}"
        ) from None
    return resolve(platform, family).variant


def by_id(record_id: str) -> ABIDef:
    """The record whose id is `record_id` (``"X86_64/LITTLE:sysv"``).

    Raises:
        ValueError: If there is no such record.
        ABITablesUnavailable: If the ABI tables did not load.
    """
    try:
        return _registry().by_id[record_id]
    except KeyError:
        raise ValueError(f"no ABI record with id {record_id!r}") from None


def all_records() -> typing.Tuple[ABIDef, ...]:
    """Every record, in table order.

    Raises:
        ABITablesUnavailable: If the ABI tables did not load.
    """
    return _registry().records


__all__ = [
    "DATA_MODULE",
    "all_records",
    "by_id",
    "default_variant",
    "maybe_resolve",
    "mechanics_for",
    "resolve",
    "table_features",
    "tables_available",
    "variants",
]


# Load the tables now, once. Every lookup is served from the result.
_tables = _load(DATA_MODULE)
