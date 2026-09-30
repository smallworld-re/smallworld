"""The ABI record registry and lookups.

Records come from a data module, :data:`DATA_MODULE`, that exposes
``RECORDS: Tuple[ABIDef, ...]`` built from plain constructor calls over
literals. That module is generated when smallworld is built or installed and
is not part of the source tree, so it may be absent. The registry is built
lazily, on the first lookup, never at import: ``import smallworld`` (and
``import smallworld.platforms.abi``) always succeeds and loads no tables.

When the data module is missing or fails to load, every lookup -- including
:func:`maybe_resolve` and the listing functions -- raises
:class:`~smallworld.platforms.abi.errors.ABITablesUnavailable`, so a missing
install step is never mistaken for "not modelled". That is the case in
builds that did not generate tables: source checkouts, and Python 3.9 and
3.11 builds. :func:`tables_available` and :func:`table_features` describe the
tables without raising.

The load is attempted once per process: its result, success or failure, is
kept, so tables installed while the process runs are not picked up.
"""

import contextlib
import importlib
import threading
import traceback
import typing

from ..platforms import ABI, Platform
from .errors import ABITablesUnavailable
from .model import ABIDef

#: The module the tables are loaded from. It must define ``RECORDS``, a tuple
#: of :class:`ABIDef`, and may define ``FEATURES``, a tuple of the table
#: feature names it provides (see :func:`table_features`).
DATA_MODULE = "smallworld.platforms.abi._data"

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


# Reentrant, so that a lookup made while DATA_MODULE is being imported (by
# the data module itself, or by something it imports) raises instead of
# deadlocking; see _data_registry().
_lock = threading.RLock()
#: True while this thread is importing DATA_MODULE (only read under _lock).
_loading = False
#: The registry built from DATA_MODULE, once it has loaded.
_loaded: typing.Optional[_Registry] = None
#: Why DATA_MODULE failed to load, once it has; re-raised by every lookup.
_load_failure: typing.Optional[ABITablesUnavailable] = None
#: A record set installed by _use_records(); takes precedence over _loaded.
_override: typing.Optional[_Registry] = None


def _load_data_module() -> _Registry:
    try:
        module = importlib.import_module(DATA_MODULE)
    except ModuleNotFoundError as e:
        if e.name == DATA_MODULE:
            raise ABITablesUnavailable(
                f"no ABI tables are installed ({DATA_MODULE} does not exist); "
                "they are generated when smallworld is built or installed, and "
                "source checkouts and Python 3.9 and 3.11 builds have none"
            ) from None
        raise ABITablesUnavailable(
            f"the ABI tables in {DATA_MODULE} failed to load"
        ) from e
    except Exception as e:
        raise ABITablesUnavailable(
            f"the ABI tables in {DATA_MODULE} failed to load"
        ) from e
    records = getattr(module, "RECORDS", None)
    if not isinstance(records, tuple):
        raise ABITablesUnavailable(f"{DATA_MODULE} does not define a RECORDS tuple")
    features = getattr(module, "FEATURES", ())
    if not (isinstance(features, tuple) and all(isinstance(f, str) for f in features)):
        raise ABITablesUnavailable(
            f"{DATA_MODULE}.FEATURES must be a tuple of strings, not {features!r}"
        )
    try:
        return _Registry(records, DATA_MODULE, features)
    except (TypeError, ValueError) as e:
        raise ABITablesUnavailable(
            f"the ABI tables in {DATA_MODULE} are invalid"
        ) from e


class _LoadFailureCause(Exception):
    """The formatted cause of a cached load failure.

    It holds only text, so a cached failure keeps no frame, and no object
    from the failed import, alive.
    """

    pass


def _detached(error: ABITablesUnavailable) -> ABITablesUnavailable:
    """A copy of `error` that holds no frames.

    A raised exception's traceback (and its cause's and context's, and any
    exception among their arguments) keeps every frame it passed through
    alive, locals included. The cached failure outlives the lookup that
    caused it, so it keeps only text: the message, and the cause chain
    formatted as ``traceback.format_exception`` prints it.
    """
    detached = ABITablesUnavailable(str(error))
    cause = error.__cause__
    if cause is None:
        detached.__suppress_context__ = True
        return detached
    text = "".join(
        traceback.format_exception(type(cause), cause, cause.__traceback__)
    ).rstrip()
    detached.__cause__ = _LoadFailureCause(text)
    return detached


def _raise_load_failure(failure: ABITablesUnavailable) -> typing.NoReturn:
    # A fresh exception each time, so the cached one never gains a traceback.
    raise ABITablesUnavailable(*failure.args) from failure.__cause__


def _data_registry() -> _Registry:
    """The registry built from DATA_MODULE, loading it on first use.

    Only the first call attempts the load; a failure is cached and re-raised
    by every later call (see :func:`_reset`).
    """
    global _loaded, _loading, _load_failure
    registry = _loaded
    if registry is not None:
        return registry
    failure = _load_failure
    if failure is not None:
        _raise_load_failure(failure)
    with _lock:
        if _load_failure is not None:
            _raise_load_failure(_load_failure)
        if _loaded is None:
            if _loading:
                # Only the loading thread gets past the lock while _loading
                # is set, so this is a lookup from inside the import.
                raise ABITablesUnavailable(
                    f"the ABI tables were looked up while {DATA_MODULE} "
                    "was being imported"
                )
            _loading = True
            try:
                _loaded = _load_data_module()
            except ABITablesUnavailable as e:
                # This caller gets the original, with its full traceback;
                # later lookups re-raise a copy that holds no frames.
                _load_failure = _detached(e)
                raise
            finally:
                _loading = False
        return _loaded


def _reset() -> None:
    """Forget the loaded tables or the cached load failure (test hook).

    The next lookup attempts the load again.
    """
    global _loaded, _load_failure
    with _lock:
        _loaded = None
        _load_failure = None


def _registry() -> _Registry:
    override = _override
    if override is not None:
        return override
    return _data_registry()


def tables_available() -> bool:
    """Whether the ABI tables in :data:`DATA_MODULE` are installed and load.

    Attempts the load if it has not happened yet. Never raises. False in
    builds that did not generate tables: source checkouts, and Python 3.9
    and 3.11 builds.
    """
    try:
        _data_registry()
    except ABITablesUnavailable:
        return False
    return True


def table_features() -> typing.FrozenSet[str]:
    """The feature names the installed ABI tables provide.

    Read from the ``FEATURES`` tuple of :data:`DATA_MODULE`; ``frozenset()``
    when the module defines none or there are no tables. This describes the
    generated data; :data:`smallworld.platforms.abi.API_FEATURES` describes
    the code. Attempts the load if it has not happened yet. Never raises.
    """
    try:
        return _data_registry().features
    except ABITablesUnavailable:
        return frozenset()


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
    with _lock:
        previous = _override
        _override = registry
    try:
        yield
    finally:
        with _lock:
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
        ABITablesUnavailable: If no ABI tables are installed, as in builds
            that did not generate tables: source checkouts, and Python 3.9
            and 3.11 builds.
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
        ABITablesUnavailable: If no ABI tables are installed, rather than
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
        ABITablesUnavailable: If no ABI tables are installed.
    """
    return _registry().variants.get(platform, ())


def default_variant(platform: Platform, container: str = "elf") -> str:
    """The default variant for `platform` in a binary of kind `container`.

    ``"elf"`` gives the platform default; ``"pe"`` the WINDOWS family
    default.

    Raises:
        ValueError: If `container` is unknown or there is no such record.
        ABITablesUnavailable: If no ABI tables are installed.
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
        ABITablesUnavailable: If no ABI tables are installed.
    """
    try:
        return _registry().by_id[record_id]
    except KeyError:
        raise ValueError(f"no ABI record with id {record_id!r}") from None


def all_records() -> typing.Tuple[ABIDef, ...]:
    """Every record, in table order.

    Raises:
        ABITablesUnavailable: If no ABI tables are installed.
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
