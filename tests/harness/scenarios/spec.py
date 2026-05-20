from __future__ import annotations

import dataclasses
from typing import Any, Callable, Mapping, Sequence, Union

VariantInfo = tuple[str, "str | None", dict[str, Any]]
VariantsSource = Callable[[], Sequence[VariantInfo]]

ExpectationItem = tuple[tuple[str, ...], str]
StaticExpectations = Sequence[ExpectationItem]
DynamicExpectations = Callable[[str, Mapping[str, Any]], StaticExpectations]
Expectations = Union[StaticExpectations, DynamicExpectations]

RunFactory = Callable[["ScenarioInfo", str, Mapping[str, Any]], Callable[[Any], None]]
DescriptionFactory = Callable[[str, Mapping[str, Any]], "str | None"]


@dataclasses.dataclass(frozen=True)
class ScenarioInfo:
    """Declarative scenario metadata consumed by the generic manifest builder.

    A scenario module exports ``SCENARIO_INFO`` (or ``SCENARIO_INFOS``); the
    manifest's ``all_cases()`` discovers them and emits ``CaseSpec`` objects
    without per-scenario boilerplate.
    """

    prefix: str
    scenario: str
    tags: tuple[str, ...] = ()
    variants_source: VariantsSource | None = None
    run_factory: RunFactory | None = None
    weight: int = 1
    description: str | None = None
    description_factory: DescriptionFactory | None = None


def from_legacy(
    suite_names: tuple[str, ...],
    *,
    prefix: str | None = None,
) -> VariantsSource:
    """Variants enumerated from LEGACY_MATRIX. Use for scenarios that still
    round-trip through the legacy parity check.
    """

    def _impl() -> Sequence[VariantInfo]:
        from ..manifest import _legacy_variants

        return _legacy_variants(suite_names, prefix=prefix)

    return _impl


def from_arch_table(specs: Mapping[str, Any]) -> VariantsSource:
    """Variants enumerated directly from a ``{arch: spec}`` dict. The native
    counterpart to :func:`from_legacy` — pairs every supported engine with its
    arch to produce variant ids like ``"amd64"`` and ``"amd64.angr"``.
    """

    def _impl() -> Sequence[VariantInfo]:
        out: list[VariantInfo] = []
        for arch in sorted(specs):
            spec = specs[arch]
            for engine in spec.engines:
                variant = arch if engine == "unicorn" else f"{arch}.{engine}"
                out.append((variant, None, {}))
        return out

    return _impl


def _resolve_expectations(
    expectations: Expectations,
    variant: str,
    kwargs: Mapping[str, Any],
) -> Sequence[ExpectationItem]:
    if callable(expectations):
        return expectations(variant, kwargs)
    return expectations


def assert_outputs(
    expectations: Expectations,
    *,
    case_sensitive: bool = True,
    stdin: str | None = None,
    env: Mapping[str, str] | None = None,
) -> RunFactory:
    """Run-factory: call ``run_case.py`` once per ``(args, expected_substring)``
    and assert that stdout contains ``expected_substring``. ``expectations``
    may also be a callable ``(variant, kwargs) -> [(args, expected), ...]``
    for variant-dependent assertions.
    """

    def factory(
        info: ScenarioInfo,
        variant: str,
        kwargs: Mapping[str, Any],
    ) -> Callable[[Any], None]:
        resolved = _resolve_expectations(expectations, variant, kwargs)

        def run(runner: Any) -> None:
            from ..manifest import _run_case_command

            for args, expected in resolved:
                stdout, _ = _run_case_command(
                    runner,
                    info.scenario,
                    variant,
                    *args,
                    stdin=stdin,
                    env=env,
                )
                if case_sensitive:
                    runner.assert_contains(stdout, expected)
                else:
                    runner.assert_contains(stdout.lower(), expected.lower())

        return run

    return factory


def assert_contains(
    text: str,
    *,
    args: tuple[str, ...] = (),
    stdin: str | None = None,
    env: Mapping[str, str] | None = None,
    case_sensitive: bool = True,
) -> RunFactory:
    """Run-factory: call ``run_case.py`` once with ``args`` and assert
    ``text`` appears in stdout. Sugar over :func:`assert_outputs` for the
    one-call-one-assertion case.
    """

    return assert_outputs(
        ((args, text),),
        case_sensitive=case_sensitive,
        stdin=stdin,
        env=env,
    )


def just_run(
    *,
    args: tuple[str, ...] = (),
    stdin: str | None = None,
    env: Mapping[str, str] | None = None,
) -> RunFactory:
    """Run-factory: call ``run_case.py`` once with ``args`` and rely on the
    subprocess exit code for success. No stdout assertion.
    """

    def factory(
        info: ScenarioInfo,
        variant: str,
        kwargs: Mapping[str, Any],
    ) -> Callable[[Any], None]:
        def run(runner: Any) -> None:
            from ..manifest import _run_case_command

            _run_case_command(
                runner,
                info.scenario,
                variant,
                *args,
                stdin=stdin,
                env=env,
            )

        return run

    return factory
