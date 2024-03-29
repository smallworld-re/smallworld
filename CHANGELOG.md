# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- `Memory` state objects with large values are now stringified much faster.

### Added
- `AngrEmulator` based on angr symbolic execution.
- `AngrNWBTAnalysis` unused value analysis using angr.
- `ELFImage` state object that loads an ELF file.
- `Filter` analyses that simply listen to the hint stream.
- `Instruction` classes that provide information on instruction semantics, with
  methods for capturing concrete values.
- `ControlFlowTracer` analysis that logs all jumps, calls, and returns.

### Changed
- `State.map()` automatically selects names for mapped objects when not
  provided.
- `UnicornEmulator` captures more detailed error information in single step
  mode.
- `UnicornEmulator.write_memory()` now supports overlapping writes and no
  longer requires addresses to be page aligned.

## [0.0.1] - 2024-02-26

### Added
- Initial public SmallWorld demo.

[unreleased]: https://github.com/smallworld-re/smallworld/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/smallworld-re/smallworld/releases/tag/v0.0.1
