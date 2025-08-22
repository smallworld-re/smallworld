# Tests

A collection of interesting test cases for analysis, documented with comments.

## Organization

Each sub-directory contains cross-architecture variants
of a single test case, along with scripts to exercise
that test for each relevant emulator:

- `test.arch.s`: Assembly for building a raw binary for `test` for `arch`.
- `test.arch.elf.s`: Assembly for building an ELF executable for `test` for `arch`.
- `test.elf.c`: C for building ELF executable files for `test` for all viable architectures.
- `test.so.c`: C for building all ELF shared object files for `test` for all viable architectures.
- `test.pe.c`: C for building all PE executable files for `test` for all viable architectures.
- `test.arch.py`: Script for exercising the test case using Unicorn.
- `test.arch.angr.py`: Script for exercising the test case using angr.
- `test.arch.panda.py`: Script for exercising the test case using Panda.

The library model test cases have an extra layer of organization.
Test cases for specific functions are grouped by API standard, 
e.g.: `c99/atoi`.

There are also two test suites in the root directory:

- `unit.py`: Performs a collection of basic unit tests on the `smallworld` library
- `integration.py`: Exercises and verifies most test scripts described above.

Internally, `integration.py` groups tests into suites under a single class,
with each suite containing multiple test cases,
usually testing the same behavior for different combinations
of platform and emulator.

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

Tests can be run individually, or as part of the integration suite.

The test binaries need to be compiled before the tests can be run.
Thus, the suite is not fully supported on a platform without cross-compiler support.

#### Integration Tests

The integration test script can run all tests, a single suite, or a single case.

```bash
python3 integration.py                      # Executes all test cases
python3 integration.py SuiteTests           # Execute all test cases in one suite
python3 integration.py SuiteTests.test_case # Execute a single test case
```

Some features of smallworld are optional, given dependencies on large external libraries.
The integration tests assume that all features are present.

#### Test Cases

The individual test cases can be run on their own:

```bash
python3 test.arch.emulator.py
```

Some test cases require arguments.  See the specific scripts for details.
