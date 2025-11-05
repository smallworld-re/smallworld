.. _installation:

Installation Guide
==================

Prerequisites
-------------

SmallWorld is supported by `Python <https://www.python.org/downloads/>`_
(>=3.10) on Linux and is installed with `pip
<https://pip.pypa.io/en/stable/>`_. Both Python and pip must be installed on
your system before attempting to install SmallWorld.

.. note::
   SmallWorld is very particular about the versions of its pip dependencies.
   Please install in a `virtual environment <https://docs.python.org/3/library/venv.html>`_.

Basic Installation
------------------

SmallWorld can be installed solely as a Python project.
This will provide access to the Unicorn and angr emulation features.

Ghidra and Panda emulation, plus fuzzing with ``unicornafl``,
requires more dependencies.  See "Complete Installation" for details.

Basic Install from PyPI
***********************

SmallWorld is available as a `pip package <https://pypi.org/project/smallworld-re/>`_ package.

It can be installed using

.. code-block:: bash

    pip install smallworld-re

Basic Install from Source
*************************

SmallWorld source is available from  `from GitHub
<https://github.com/smallworld-re/smallworld>`_

To clone the source code, run:

.. code-block:: bash

    git clone git@github.com:smallworld-re/smallworld.git

To perform a basic installation, run the following commands:

.. code-block:: bash

    cd smallworld
    python3 -m pip install -e . -c constraints.txt

Complete Installation
---------------------

Some of SmallWorld's features rely on native features
that cannot be reliably installed via package manager.

The following features require extra installation steps:

- User-mode emulation with Ghidra requires Ghidra
- Full-system emulation with Panda requires Panda
- Fuzzing support requires AFL++ and unicornafl.
- The example programs require a bevy of cross-compilers

We recommend the following workflows:

- For analysis and harness authoring, we recommend a partial extension of the basic install, 
  or the nix mutable environment
- For fuzzing, we recommend using the nix mutable environment, or the docker container
- For development, we recommend the nix immutable environment 

Extending a basic installation
******************************



We recommend developing a harness using the basic emulators,
then converting it to a fuzzing harness and exercising it
using either nix or docker.

Installing Ghidra
^^^^^^^^^^^^^^^^^

As a prerequisite, you will need Ghidra 11.3.2 or later installed,
as well as an appropriate Java JDK.
See the `Ghidra documentation <https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GettingStarted.md>`_
for details.

Assuming the ghidra installation directory is at ``GHIDRA_INSTALL_DIR``,
execute the follwing in your SmallWorld environment:

.. code-block:: bash

    python3 -m pip install --no-index -f "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra

Installing build tools
^^^^^^^^^^^^^^^^^^^^^^

Building examples for seventeen platforms requires a lot of cross-compilers.
Currently, the Makefile isn't smart enough to skip missing dependencies
gracefully.  This may change in the future.

**Ubuntu 24.04 or later:**

To install the required build tools on Ubuntu 24.04 or later,
please run the following commands:

.. code-block:: bash
    
    cd smallworld/tests

    sudo apt-get install -y $(cat dependencies/apt.txt)
    sudo apt-get install -y gcc-loongarch64-linux-gnu

**Ubuntu 22.04:**

Installing the necessary build tools on Ubuntu 22.04
takes an extra step; loongarch64 support is only available in GCC 13 or later,
which needs to be back-ported.

We provide a research-grade backported package
containing binutils, GCC 14, glibc, and kernel headers.
if you have problems with it, please let us know.

.. code-block:: bash

    cd smallworld/tests

    sudo apt-get install -y $(cat dependencies/apt.txt)

    wget  https://github.com/smallworld-re/buildtools/releases/latest/download/buildtools-loongarch64-linux-gnu.deb
    sudo apt-get install ./buildtools-loongarc64-linux-gnu.deb

.. warning:: 
    
    For some reason, Ubuntu 22.04 for aarch64
    does not include the PowerPC 32-bit cross compiler
    in its package repository.

**Debian**

It is highly possible that the apt-based install procedure
will work on some versions of Debian or related Linux distros.
This is not tested.

**Anything Else**

If you want to build the SmallWorld test cases on
another platform without Docker or nix,
you will need to provide your own build tools,
and very likely either alias them to their Debian names,
or modify the Makefile to target the correct programs.

Required dependencies:

- GNU make
- GCC targeting a POSIX-compliant environment for the following platforms:
    - aarch64 (a.k.a.: arm64)
    - amd64 (a.k.a.: x86_64)
    - arm v5t (a.k.a.: armel, or arm-linux-gnueabi)
    - arm v7a (a.k.a.: armhf, or arm-linux-gnueabihf)
    - i686 (a.k.a.: ia32, i386, or x86)
    - loongarch64
    - mips32r2 big endian (a.k.a.: mips)
    - mips32r2 little endian (a.k.a.: mipsel)
    - mips64r2 big endian (a.k.a.: mips64)
    - mips64r2 little endian (a.k.a.: mips64el)
    - PowerPC32 big endian (a.k.a.: powerpc)
    - PowerPC64 big endian (a.k.a.: powerpc64)
    - riscv64
- GCC targeting mingw for the following platforms:
    - amd64 (a.k.a.: x86_64)
    - i686 (a.k.a.: ia32, i386, or x86)
- GNU Binutils for all of the above, plus the following:
    - xtensa
- nasm

The ELF coredump examples require host support,
and probably won't work on non-Linux platforms.
They require the following extra tools:

- User-mode QEMU (tested with version 6.2.0).
- Multiarch GDB

Using nix
*********

.. warning::

    This feature is still under development;
    it's not yet available in this version of SmallWorld.

Nix is a tool for building reproducible system environments.
It sacrificies the flexibility of installing SmallWorld
into an existing environment for the ability
to install the complete set of features safely and reliably.

Nix is conceptually similar to a virtualenv;
activating the environment opens a new shell with 
a full SmallWorld environment pre-populated.

Any native executables or libraries you have installed
will still be available, but nix will override the python environment.

SmallWorld offers two nix environments:

- The "mutable" environment, suitable for SmallWorld users
- The "immutable" environment, suitable for SmallWorld developers

Nix mutable environment
^^^^^^^^^^^^^^^^^^^^^^^

The mutable environment is designed for users;
it will present you with a Python venv that's pre-populated
with SmallWorld and all of its dependencies.

The following command will open a nix shell
with the mutable environment configured:

.. code-block:: bash

    cd smallworld
    nix develop.#mutable

You can access ``pip`` using ``uv pip`` as the base command,
and are free to install your own packages.
These will not modify the SmallWorld installation,
and will persist if you close and reopen the nix shell.

Nix immutable environment
^^^^^^^^^^^^^^^^^^^^^^^^^
The immutable environment is designed for 
developers working on SmallWorld.
It offers more features for tracking
changes to the SmallWorld environment,
at the cost of some flexibility.

The following command will open a nix shell
with the immutable environment configured:

.. code-block:: bash
    
    cd smallworld
    nix develop

The only difference here is that you must use ``uv`` to manage the environment.
Changes to your python environment are tracked by ``uv``,
and will automatically update ``pyproject.toml``,
as well as the nix configuration in order to track native libraries.

Nix .drv deployment
^^^^^^^^^^^^^^^^^^^

.. warning::
    TODO: Figure out how this works

Using docker
************


