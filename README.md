# SmallWorld

[![commit-style-image]][conventional]
[![code-style-image]][black]
[![license-image]][mit]

Easier harnessing of code for analysis!

## Description

SmallWorld is an environment for streamlined harnessing of binary code for the
purpose of dynamic analysis. If you have code that you got from somewhere and
you'd like to run it and analyze those runs to understand what that code does
or if it has bugs, then you should try SmallWorld!!

There are two fundamental tenets behind SmallWorld
* Harnessing should be easier
* Analysis can accelerate harnessing

The first of these tenets we hope to support with good software APIs. As a very
simple example, consider the harnessing script
[square.amd64.py](https://github.com/smallworld-re/smallworld/blob/main/tests/square/square.amd64.py),
composed using SmallWorld, in which registers are initialized and a stack is
arranged for running the code in
[square.amd64.s](https://github.com/smallworld-re/smallworld/blob/main/tests/square/square.amd64.s).
For a more sophisticated example of SmallWorld's harnessing facitilites,
consider the code snippet
[struct.amd64.s](https://github.com/smallworld-re/smallworld/blob/main/tests/struct/struct.amd64.s),
which assumes a stack and input pointers to a linked list with very specific
format. The harnessing script in this case is more complicated, including
specifying type information for the linked list element structures as well as
use of a simple allocator abstraction provided by SmallWorld to instantiate
nodes and link them together appropriately:
[struct.amd64.py](https://github.com/smallworld-re/smallworld/blob/main/tests/struct/struct.amd64.py).

The second tenet we address with purpose-built analyses which leverage a
(possibly incomplete) harness script and that use techniques such as [Micro
Execution](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/microx.pdf)
and [Symbolic
Execution](https://en.wikipedia.org/wiki/Symbolic_execution#:~:text=In%20computer%20science%2C%20symbolic%20execution,of%20a%20program%20to%20execute)
to provide hints that can guide improving a harness. 

This harness is the final output of SmallWorld and might be used in fuzzing or
dynamic reverse engineering. Note that these are not applications which
SmallWorld directly supports yet.


## Installation

SmallWorld can be installed [directly from PyPi](https://pypi.org/project/smallworld-re/), just:
```bash
pip install smallworld-re
```

If you'd like to install the latest changes or do development, you can install directly. To install SmallWorld from this repo, [optionally set up a venv](https://docs.python.org/3/library/venv.html) and then run:

```bash
pip install .
```

The result will be a library that can be used for harnessing and analyzing.  See the examples for a walkthrough.

## Contributing

Pull requests and issues more than welcome.

### Development

#### The Easy Way
To set up a development environment from this repo, the easiest method is to use
the install script `install.sh`. This has been tested on Ubuntu 22.04 and may be run
as the root user, or a non-root user with sudo permissions.
This will both install SmallWorld and build the unit and integration tests.
Note that installation will not work fully on an ARM and is not supported.

#### The Hard Way
To manually set up a development environment from this repo, install SmallWorld in
editable mode with extras for development and testing. Use the include
constraints to install frozen versions and ensure a consistent development
environment.

```bash
pip install -e .[development] -c constraints.txt
```

#### Code Style

Pre-commit hooks are available for automatic code formatting, linting, and type
checking via [pre-commit](https://pre-commit.com/). To enable them (after
installing development dependencies), run:

```bash
pre-commit install
```

### Testing

#### Prerequisites

Building the test binaries requires some dependencies which can be installed
with:

```bash
apt-get install `cat tests/dependencies/apt.txt`
```

You can then build the tests by running:

```bash
make -C tests

ulimit -c unlimited
make -C tests/elf_core
```

#### Running Tests

Once the test files have been built and SmallWorld has been installed, you can
run unit and integration tests:

```bash
python3 tests/unit.py
python3 tests/integration.py
```

### Documentation

To build the full SmallWorld documentation
* verify [Sphinx](https://www.sphinx-doc.org/) has been installed
* install SmallWorld with `development` extras enabled
* make sure you have built the tests since the documentation generation requires output from those tests
* from the `docs/` directory, run:

```bash
make html
```

The resulting documentation will be in `docs/build/html/`

Other [supported Sphinx output formats](https://www.sphinx-doc.org/en/master/usage/builders/index.html) can also be generated.


## Distribution

DISTRIBUTION STATEMENT A. Approved for public release. Distribution is
unlimited.

This material is based upon work supported by the Under Secretary of Defense
for Research and Engineering under Air Force Contract No. FA8702-15-D-0001. Any
opinions, findings, conclusions or recommendations expressed in this material
are those of the author(s) and do not necessarily reflect the views of the
Under Secretary of Defense for Research and Engineering.

Delivered to the U.S. Government with Unlimited Rights, as defined in DFARS
Part 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice,
U.S. Government rights in this work are defined by DFARS 252.227-7013 or DFARS
252.227-7014 as detailed above. Use of this work other than as specifically
authorized by the U.S. Government may violate any copyrights that exist in this
work.

[MIT License](LICENSE.txt)

[commit-style-image]: https://img.shields.io/badge/commits-conventional-fe5196.svg
[conventional]: https://www.conventionalcommits.org/en/v1.0.0/
[code-style-image]: https://img.shields.io/badge/code%20style-black-000000.svg
[black]: https://github.com/psf/black
[license-image]: https://img.shields.io/badge/license-MIT-green.svg
[mit]: ./LICENSE.txt
