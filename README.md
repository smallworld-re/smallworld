# SmallWorld

[![commit-style-image]][conventional]
[![code-style-image]][black]
[![license-image]][mit]

An emulation state tracking library and tool.

## Description

Coming soon...

## Installation

To install SmallWorld from this repo, run:

```bash
pip install .
```

## Usage

Print basic usage and help:

```bash
smallworld --help
```

## Contributing

Pull requests and issues more than welcome.

### Development

To set up a development environment from this repo, install SmallWorld in
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

### Documentation

To build the full SmallWorld documentation, after installing SmallWorld with
`development` extras enabled, from the `docs/` directory, run:

```bash
make html
```

Or other [supported Sphinx output formats](https://www.sphinx-doc.org/en/master/usage/builders/index.html).

### Testing

#### Prerequisites

Building the test binaries requires `nasm`, which can be installed with:

```bash
apt-get install nasm
```

You can then build the tests by running:

```bash
make -C tests
```

#### Running Tests

Once the test files have been built and SmallWorld has been installed, you can
run integration tests:

```bash
python tests/integration.py
```

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
