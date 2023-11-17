# Small World

[![code-style-image]][black]
[![license-image]][mit]

An emulation state tracking library and tool.

## Description

Coming soon...

## Installation

To install Small World from this repo, run:

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

To set up a development environment from this repo, install Small World in
editable mode with extras for development and testing.

```bash
pip install -e .[development]
```

It can also be helpful to install frozen versions of dependencies to ensure a
consistent development environment. From this repo, run:

```bash
pip install -r requirements.txt
```

### Code Style

Pre-commit hooks are available for automatic code formatting, linting, and type
checking via [pre-commit](https://pre-commit.com/). To enable them (after
installing development dependencies), run:

```bash
pre-commit install
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

[code-style-image]: https://img.shields.io/badge/code%20style-black-000000.svg
[black]: https://github.com/psf/black
[license-image]: https://img.shields.io/badge/license-MIT-green.svg
[mit]: ./LICENSE.txt
