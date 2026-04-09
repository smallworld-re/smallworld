# Tests

A collection of SmallWorld integration scenarios, library-model checks, and unit
tests.

## Organization

Many scenario directories contain:

- `test.arch.s`: Assembly for building a raw binary for `test` for `arch`.
- `test.arch.elf.s`: Assembly for building an ELF executable for `test` for `arch`.
- `test.elf.c`: C for building ELF executable files for `test` for all viable architectures.
- `test.so.c`: C for building all ELF shared object files for `test` for all viable architectures.
- `test.pe.c`: C for building all PE executable files for `test` for all viable architectures.
- `test.arch.py`: A legacy Unicorn harness for one platform, if that family has
  not been migrated yet.
- `test.arch.angr.py`: A legacy angr harness for one platform, if that family
  has not been migrated yet.
- `test.arch.panda.py`: A legacy Panda harness for one platform, if that family
  has not been migrated yet.

The supported entrypoint for running one scenario is `run_case.py` rather than
calling the files in a scenario directory directly.
Refactored families live under `harness/scenarios/`, where one shared Python
module handles the full scenario matrix and `run_case.py` uses that
implementation directly. Legacy wrapper scripts remain only for the families
that have not been migrated yet.

The library-model tests have an extra layer of organization. Test cases for
specific functions are grouped by API standard, for example `c99/atoi`.

There are also two test suites in the root directory:

- `unit.py`: Performs a collection of basic unit tests on the `smallworld` library
- `integration.py`: Runs the manifest-driven integration suite
- `run_case.py`: Runs one scenario/variant pair through a stable CLI

Internally, `integration.py` builds a manifest of cases with ids like
`square:amd64` or `c99:memcpy:mips`. CI shards that manifest in parallel instead
of relying on `unittest` suite class names.

## Usage

### Dependencies

Install dependencies for these tests by running:

#### Ubuntu

```bash
sudo apt-get install `cat dependencies/apt.txt`
```

### Compiling

To build all of the tests, run:

```bash
make
make -C elf_core    # NOTE: Requires `ulimit --core` to be set
```

### Running

Tests can be run individually, listed, filtered, or executed as part of the
full integration suite.

The test binaries need to be compiled before the tests can be run.
Thus, the suite is not fully supported on a platform without cross-compiler support.

#### Integration Tests

The integration runner works from case ids and filters:

```bash
python3 integration.py                               # Execute all manifest cases
python3 integration.py --filter square               # Run matching ids/tags
python3 integration.py --filter '^square:'           # Run only the square family
python3 integration.py --list                        # List all cases
python3 integration.py --list --format json         # Machine-readable listing
python3 integration.py --shard-index 0 --shard-count 8
```

Some features of smallworld are optional, given dependencies on large external libraries.
The integration tests assume that all features are present.

#### Test Cases

Run a single scenario through the stable wrapper:

```bash
python3 run_case.py square amd64 42
python3 run_case.py checked_heap.read amd64.angr
python3 run_case.py elf_core.actuate amd64
```

Some scenarios require extra arguments. See the underlying harness script for
details.
