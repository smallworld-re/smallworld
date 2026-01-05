# SmallWorld

[![commit-style-image]][conventional]
[![code-style-image]][black]
[![license-image]][mit]

Easier harnessing of code for analysis!

## Quick Start
Our documentation is currently being updated. To get up and running quickly try the following:

On Linux install nix with flakes enabled. We recommend the [Determinate Systems nix installer](https://docs.determinate.systems/).

Download the script found in `examples/nix-harness.py`.

Then run:
```
  nix run nixpkgs#cachix -- use smallworld
  chmod +x nix-harness.py
  ./nix-harness.py 10
```
See the comments in the python script for more details.

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
