from __future__ import annotations

from .spec import ScenarioInfo, from_variants, script_assert_lines

NATIVE_PARITY = True

SCENARIO_INFO = ScenarioInfo(
    prefix="fsgsbase",
    scenario="fsgsbase",
    tags=("scenario", "fsgsbase"),
    variants_source=from_variants((("amd64", None),)),
    run_factory=script_assert_lines(
        (
            "Here's where in fs segment lsb of rax is: 40. ... which is correct.  Looks like fs:[0x28] address is working properly.",
            "Here's where in gs segment lsb of rbx is: 19. ... which is correct.  Looks like gs:[0x13] address is working properly.",
        ),
        script_template="fsgsbase/fsgsbase.{variant}.py",
    ),
)
