from __future__ import annotations

import io
from typing import Any, Mapping

from .common import RepoRoot
from .spec import ScenarioInfo, from_variants

NATIVE_PARITY = True


def _documentation_run_factory(info, variant: str, kwargs: Mapping[str, Any]):
    def run(_runner):
        from sphinx import application, errors

        source = RepoRoot / "docs"
        build = source / "build"
        doctree = build / "doctrees"
        warnings = io.StringIO()
        app = application.Sphinx(
            str(source),
            str(source),
            str(build),
            str(doctree),
            "html",
            status=None,
            warning=warnings,
        )
        app.build()
        warnings.flush()
        warnings.seek(0)
        content = warnings.read().strip()
        if content:
            raise errors.SphinxWarning(f"\n\n{content}")

    return run


SCENARIO_INFO = ScenarioInfo(
    prefix="documentation",
    scenario="documentation",
    tags=("docs",),
    variants_source=from_variants((("build", None),)),
    run_factory=_documentation_run_factory,
    weight=3,
)
