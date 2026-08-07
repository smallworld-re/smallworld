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


def from_arch_table(
    specs: Mapping[str, Any],
    *,
    skip_reasons: Mapping[str, str] | None = None,
    arch_kwargs: Mapping[str, Mapping[str, Any]] | None = None,
    extra_variants: Sequence["VariantInfo"] = (),
) -> VariantsSource:
    """Variants enumerated directly from a ``{arch: spec}`` dict. Pairs every
    supported engine with its arch to produce variant ids like ``"amd64"`` and
    ``"amd64.angr"``.

    ``skip_reasons`` maps a specific variant to its skip reason. ``arch_kwargs``
    attaches a kwargs dict to every variant of a given arch (used by run-factories
    that vary expectations per arch, e.g. signext or sixteenbit). ``extra_variants``
    is appended verbatim after the arch×engine grid, for variants that don't fit
    the standard enumeration (e.g. a hand-rolled spec override).
    """

    skips = dict(skip_reasons or {})
    arch_kw = {arch: dict(kw) for arch, kw in (arch_kwargs or {}).items()}

    def _impl() -> Sequence[VariantInfo]:
        out: list[VariantInfo] = []
        for arch in sorted(specs):
            spec = specs[arch]
            kwargs = arch_kw.get(arch, {})
            for engine in spec.engines:
                variant = arch if engine == "unicorn" else f"{arch}.{engine}"
                out.append((variant, skips.get(variant), dict(kwargs)))
        out.extend(extra_variants)
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


VariantTransform = Callable[[str], str]


def _identity_variant(variant: str) -> str:
    return variant


def from_variants(
    variants: Sequence[tuple[str, "str | None"]],
    *,
    kwargs: Mapping[str, Mapping[str, Any]] | None = None,
) -> VariantsSource:
    """Variants enumerated from an explicit ``[(variant, skip_reason), ...]``
    list. ``kwargs`` optionally attaches a per-variant kwargs dict, used by
    run-factories that vary expectations per variant.
    """
    kw = {variant: dict(item) for variant, item in (kwargs or {}).items()}
    frozen = tuple((v, s) for v, s in variants)

    def _impl() -> Sequence[VariantInfo]:
        return tuple((v, s, dict(kw.get(v, {}))) for v, s in frozen)

    return _impl


def script_just_run(
    *,
    script_template: str,
    args: tuple[str, ...] = (),
    stdin: str | None = None,
    env: Mapping[str, str] | None = None,
    variant_transform: VariantTransform = _identity_variant,
) -> RunFactory:
    """Run-factory: invoke the variant-specific test script directly (bypassing
    ``run_case.py``) and rely on subprocess exit code for success.
    ``script_template`` is a format string like ``"floats/floats.{variant}.py"``.
    """

    def factory(
        info: ScenarioInfo,
        variant: str,
        kwargs: Mapping[str, Any],
    ) -> Callable[[Any], None]:
        script = script_template.format(variant=variant_transform(variant))

        def run(runner: Any) -> None:
            from ..manifest import _run_script

            _run_script(runner, script, *args, stdin=stdin, env=env)

        return run

    return factory


def script_assert_outputs(
    expectations: Expectations,
    *,
    script_template: str,
    case_sensitive: bool = True,
    stdin: str | None = None,
    env: Mapping[str, str] | None = None,
    line: bool = False,
    variant_transform: VariantTransform = _identity_variant,
) -> RunFactory:
    """Run-factory: invoke the variant-specific script once per
    ``(args, expected)`` pair and assert stdout contains ``expected``.
    Set ``line=True`` for line-anchored assertions.
    """

    def factory(
        info: ScenarioInfo,
        variant: str,
        kwargs: Mapping[str, Any],
    ) -> Callable[[Any], None]:
        resolved = _resolve_expectations(expectations, variant, kwargs)
        script = script_template.format(variant=variant_transform(variant))

        def run(runner: Any) -> None:
            from ..manifest import _run_script

            for args, expected in resolved:
                stdout, _ = _run_script(
                    runner,
                    script,
                    *args,
                    stdin=stdin,
                    env=env,
                )
                target = stdout if case_sensitive else stdout.lower()
                needle = expected if case_sensitive else expected.lower()
                if line:
                    runner.assert_line_contains(target, needle)
                else:
                    runner.assert_contains(target, needle)

        return run

    return factory


def script_assert_lines(
    lines: Sequence[Any],
    *,
    script_template: str,
    args: tuple[str, ...] = (),
    stdin: str | None = None,
    env: Mapping[str, str] | None = None,
    variant_transform: VariantTransform = _identity_variant,
) -> RunFactory:
    """Run-factory: invoke the variant-specific script **once** and assert each
    entry in ``lines`` matches a stdout line. Each entry may be a ``str`` (one
    substring) or a ``tuple[str, ...]`` (multiple substrings required on the
    same line). ``lines`` may also be a callable ``(variant, kwargs) -> lines``
    for variant-dependent assertions.
    """

    def factory(
        info: ScenarioInfo,
        variant: str,
        kwargs: Mapping[str, Any],
    ) -> Callable[[Any], None]:
        resolved = lines(variant, kwargs) if callable(lines) else lines
        script = script_template.format(variant=variant_transform(variant))

        def run(runner: Any) -> None:
            from ..manifest import _run_script

            stdout, _ = _run_script(runner, script, *args, stdin=stdin, env=env)
            for entry in resolved:
                parts = (entry,) if isinstance(entry, str) else tuple(entry)
                runner.assert_line_contains(stdout, *parts)

        return run

    return factory


def script_assert_contains(
    text: str,
    *,
    script_template: str,
    args: tuple[str, ...] = (),
    stdin: str | None = None,
    env: Mapping[str, str] | None = None,
    case_sensitive: bool = True,
    line: bool = False,
    variant_transform: VariantTransform = _identity_variant,
) -> RunFactory:
    """Sugar over :func:`script_assert_outputs` for the
    one-invocation-one-assertion case.
    """

    return script_assert_outputs(
        ((args, text),),
        script_template=script_template,
        case_sensitive=case_sensitive,
        stdin=stdin,
        env=env,
        line=line,
        variant_transform=variant_transform,
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
