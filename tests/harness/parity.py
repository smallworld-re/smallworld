from __future__ import annotations

from .legacy_library import LEGACY_LIBRARY_MODELS
from .legacy_matrix import LEGACY_MATRIX
from .scenarios import fuzz
from .scenarios.registry import REGISTERED_SCENARIOS

GENERIC_SUITES = {
    "BlockTests": ("block", "block"),
    "BranchTestsAngr": ("branch", "branch"),
    "BranchTestsGhidra": ("branch", "branch"),
    "BranchTestsPanda": ("branch", "branch"),
    "BranchTestsUnicorn": ("branch", "branch"),
    "CallTestsAngr": ("call", "call"),
    "CallTestsGhidra": ("call", "call"),
    "CallTestsPanda": ("call", "call"),
    "CallTestsUnicorn": ("call", "call"),
    "CheckedDoubleFreeTests": ("checked_heap.double_free", None),
    "CheckedReadTests": ("checked_heap.read", None),
    "CheckedUAFTests": ("checked_heap.uaf", None),
    "CheckedWriteTests": ("checked_heap.write", None),
    "CrashTriageTests": ("crash_triage", None),
    "DMATests": ("dma", "dma"),
    "DelayTests": ("delay", "delay"),
    "ElfCoreActuateTests": ("elf_core.actuate", None),
    "ElfCoreLoadTests": ("elf_core.load", "elf_core"),
    "ElfTests": ("elf", "elf"),
    "ExitpointTests": ("exitpoint", "exitpoint"),
    "FloatsTests": ("floats", None),
    "FunctionPointerTests": ("funcptr", None),
    "HookingTests": ("hooking", "hooking"),
    "InterruptTests": ("interrupt", None),
    "LinkElfTests": ("link_elf", "link_elf"),
    "LinkPETests": ("link_pe", "pe"),
    "MemhookTests": ("memhook", None),
    "PETests": ("pe", "pe"),
    "RecursionTests": ("recursion", "recursion"),
    "RelaTests": ("rela", "rela"),
    "SquareTests": ("square", "square"),
    "StackTests": ("stack", "stack"),
    "StaticBufferTests": ("static_buf", "static_buffer"),
    "StaticRelaTests": ("static_rela", None),
    "StrlenTests": ("strlen", "strlen"),
    "SymbolicStateTests": ("symbolic_state", None),
    "SysVModelTests": ("sysv", None),
    "SyscallTests": ("syscall", None),
    "UnmappedTests": ("unmapped", "unmapped"),
}

LIBRARY_ARCHES = [
    "aarch64",
    "amd64",
    "armel",
    "armhf",
    "i386",
    "la64",
    "m68k",
    "mips",
    "mipsel",
    "mips64",
    "mips64el",
    "ppc",
    "riscv64",
]

DIFFTIME_SKIPS = {
    "i386": "Returning float fails on i386",
    "m68k": "Returning float fails on m68k",
    "mips64": "Returning float fails on mips64",
    "mips64el": "Returning float fails on mips64el",
}


def _expected_special_cases() -> dict[str, str | None]:
    expected: dict[str, str | None] = {}

    colorizer_names = {
        "test_colors_1": "colorizer:test_colorizer_1",
        "test_colors_2": "colorizer:test_colorizer_2",
    }
    for entry in LEGACY_MATRIX["ColorizerTests"]:
        expected[colorizer_names[entry["name"]]] = entry["skip_reason"]

    for entry in LEGACY_MATRIX["CoverageFrontierTests"]:
        expected[f"coverage_frontier:{entry['name']}"] = entry["skip_reason"]

    expected["documentation:build"] = LEGACY_MATRIX["DocumentationTests"][0][
        "skip_reason"
    ]
    expected["fsgsbase:amd64"] = None
    expected["model_return:tricore.panda"] = None

    for entry in LEGACY_MATRIX["FuzzTests"]:
        stem = entry["name"][5:]
        kind, arch = stem.split("_", 1)
        case_id = f"fuzz:{arch}" if kind == "fuzz" else f"fuzz:afl:{arch}"
        expected[case_id] = entry["skip_reason"]

    for entry in LEGACY_MATRIX["LoopDetectionTests"]:
        expected["loop_detection:test_loop_detector_1"] = entry["skip_reason"]

    rtos_names = {
        "test_rtos_fuzz": "rtos_demo:rtos_1_fuzz",
    }
    for entry in LEGACY_MATRIX["RTOSDemoTests"]:
        if "run_test" in entry:
            script = entry["run_test"]["args"][0]
            expected[f"rtos_demo:{script.removesuffix('.py').split('/')[-1]}"] = entry[
                "skip_reason"
            ]
        else:
            expected[rtos_names[entry["name"]]] = entry["skip_reason"]

    structure_names = {
        "test_unicorn": "struct:amd64",
        "test_panda": "struct:amd64.panda",
    }
    for entry in LEGACY_MATRIX["StructureTests"]:
        expected[structure_names[entry["name"]]] = entry["skip_reason"]

    for entry in LEGACY_MATRIX["SymbolicTests"]:
        stem = entry["name"][5:]
        expected[f"symbolic:{stem[: -len('_symbolic')]}"] = entry["skip_reason"]

    for entry in LEGACY_MATRIX["ThumbTests"]:
        expected[f"thumb:{entry['name'][len('test_thumb_'):]}"] = entry["skip_reason"]

    for entry in LEGACY_MATRIX["TraceExecutionTests"]:
        expected[f"trace_execution:{entry['name']}"] = entry["skip_reason"]

    return expected


def _expected_library_cases() -> dict[str, str | None]:
    expected: dict[str, str | None] = {}
    for item in LEGACY_LIBRARY_MODELS:
        for arch in LIBRARY_ARCHES:
            skip_reason = None
            if item["class_name"] == "C99DifftimeTests":
                skip_reason = DIFFTIME_SKIPS.get(arch)
            expected[f"{item['library']}:{item['function']}:{arch}"] = skip_reason
    return expected


def _native_scenario_prefixes() -> set[str]:
    """Case-id prefixes for scenarios opted into the native parity tier.

    A scenario opts in by setting ``NATIVE_PARITY = True`` at module scope. Such
    scenarios bypass the LEGACY_MATRIX bijection check; the manifest becomes
    the authoritative source of truth for their case IDs and skip reasons.
    """
    return {
        prefix
        for prefix, _scenario, handler in REGISTERED_SCENARIOS
        if getattr(handler, "NATIVE_PARITY", False)
    }


def _legacy_inventory(
    exclude_prefixes: set[str] | None = None,
) -> dict[str, str | None]:
    """Case inventory derived from LEGACY_MATRIX. Scenarios in
    ``exclude_prefixes`` are skipped — they own their inventory via the
    native tier.
    """
    from .manifest import _variant_from_entry

    excluded = exclude_prefixes or set()
    expected: dict[str, str | None] = {}
    for suite_name, (case_prefix, entry_prefix) in GENERIC_SUITES.items():
        if case_prefix in excluded:
            continue
        for entry in LEGACY_MATRIX[suite_name]:
            variant, skip_reason, _ = _variant_from_entry(
                suite_name, entry, prefix=entry_prefix
            )
            expected[f"{case_prefix}:{variant}"] = skip_reason
    expected.update(_expected_special_cases())
    expected.update(_expected_library_cases())
    return expected


def _is_native_case(case_id: str, native_prefixes: set[str]) -> bool:
    for prefix in native_prefixes:
        if case_id == prefix or case_id.startswith(f"{prefix}:"):
            return True
    return False


def _native_inventory(
    actual: dict[str, str | None],
    native_prefixes: set[str],
) -> dict[str, str | None]:
    """For native-tier scenarios the manifest IS the source of truth: every
    actual case ID under a native prefix is treated as expected, and the
    associated skip reason is the one the manifest produced.
    """
    return {
        case_id: skip_reason
        for case_id, skip_reason in actual.items()
        if _is_native_case(case_id, native_prefixes)
    }


def _expected_case_inventory() -> dict[str, str | None]:
    # Retained for backwards compatibility with callers that want the legacy
    # snapshot regardless of native-tier opt-ins.
    return _legacy_inventory()


def check_manifest_parity() -> None:
    from .manifest import all_cases

    cases = [case for case in all_cases() if not case.id.startswith("parity:")]
    actual: dict[str, str | None] = {}
    duplicate_ids: list[str] = []
    for case in cases:
        if case.id in actual:
            duplicate_ids.append(case.id)
        actual[case.id] = case.skip_reason

    native_prefixes = _native_scenario_prefixes()
    native_expected = _native_inventory(actual, native_prefixes)
    legacy_expected = _legacy_inventory(exclude_prefixes=native_prefixes)

    # A native-tier scenario must not still have a LEGACY_MATRIX entry —
    # otherwise the frozen matrix has unfrozen by accident.
    full_legacy = _legacy_inventory()
    native_leaked_into_legacy = sorted(set(native_expected) & set(full_legacy))

    expected = {**legacy_expected, **native_expected}

    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    skip_mismatches = sorted(
        case_id
        for case_id, expected_skip in expected.items()
        if actual.get(case_id) != expected_skip
    )

    if (
        duplicate_ids
        or missing
        or unexpected
        or skip_mismatches
        or native_leaked_into_legacy
    ):
        details = []
        if duplicate_ids:
            details.append(f"duplicate ids: {duplicate_ids[:20]}")
        if missing:
            details.append(f"missing ids: {missing[:20]}")
        if unexpected:
            details.append(f"unexpected ids: {unexpected[:20]}")
        if skip_mismatches:
            details.append(
                "skip mismatches: "
                + str(
                    [
                        (case_id, expected[case_id], actual.get(case_id))
                        for case_id in skip_mismatches[:20]
                    ]
                )
            )
        if native_leaked_into_legacy:
            details.append(
                "native-tier scenarios still have legacy_matrix entries: "
                + str(native_leaked_into_legacy[:20])
            )
        raise AssertionError("\n".join(details))


def check_registered_scenario_parity() -> None:
    from .manifest import all_cases

    missing: list[str] = []
    for case in all_cases():
        if case.id.startswith("fuzz:"):
            parts = case.id.split(":")
            if len(parts) == 2:
                scenario = "fuzz"
                variant = parts[1]
            else:
                scenario = "fuzz.afl_fuzz"
                variant = parts[2]
            if not fuzz.can_run(scenario, variant):
                missing.append(case.id)
            continue
        matched = False
        for prefix, scenario, handler in REGISTERED_SCENARIOS:
            if case.id.startswith(f"{prefix}:"):
                matched = True
                variant = case.id[len(prefix) + 1 :]
                if not handler.can_run(scenario, variant):
                    missing.append(case.id)
                break
        if not matched and case.skip_reason is None:
            continue

    if missing:
        raise AssertionError(
            "shared scenario handlers do not cover these manifest cases: "
            + str(missing[:20])
        )
