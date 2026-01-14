.. _installation_pypi:

Minimal Install with PyPI
=========================

SmallWorld can be installed solely as a Python project.
This will provide access to the Unicorn and angr emulation features immediately,
as well as Ghidra with a tiny bit of work.

This is sufficient to write and test emulation harnesses.
Fuzzing with SmallWorld will require the Nix or Docker installation.

Prerequisites
-------------

SmallWorld is supported by `Python <https://www.python.org/downloads/>`_
(>=3.10) on Linux and is installed with `pip
<https://pip.pypa.io/en/stable/>`_. Both Python and pip must be installed on
your system before attempting to install SmallWorld.

.. note::
   SmallWorld is very particular about the versions of its pip dependencies.
   Please install in a `virtual environment <https://docs.python.org/3/library/venv.html>`_.

Basic Install from PyPI
-----------------------

SmallWorld is available as a `pip package <https://pypi.org/project/smallworld-re/>`_ package.

It can be installed using

.. code-block:: bash

    pip install smallworld-re

Basic Install from Source
-------------------------

SmallWorld source is available from  `from GitHub
<https://github.com/smallworld-re/smallworld>`_

To clone the source code, run:

.. code-block:: bash

    git clone git@github.com:smallworld-re/smallworld.git

To perform a basic installation, run the following commands:

.. code-block:: bash

    cd smallworld
    python3 -m pip install -e . -c constraints.txt



Adding Ghidra Support
---------------------

.. warning::

   The installation procedure for ``pyghidra`` does not appear to be stable,
   and the docs inside of Ghidra itself are wrong as of this writing.

   This procedure works for Ghidra 11.3.2, but will not be actively tested
   by SmallWorld moving forward.

As a prerequisite, you will need Ghidra 11.3.2 or later installed,
as well as an appropriate Java JDK.
See the `Ghidra documentation <https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GettingStarted.md>`_
for details.

Assuming the ghidra installation directory is at ``GHIDRA_INSTALL_DIR``,
execute the follwing in your SmallWorld environment:

.. code-block:: bash

    python3 -m pip install --no-index -f "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra


Compiling Example Binaries
--------------------------

.. warning::

   A number of the examples, particularly ``elf_core``,
   are bound to a specific compiler version.
   For reproducability, they are bound to the compilers
   provided in the Nix environment.

   The binaries will compile outside of that environment,
   but the harnesses will fail.

Prerequisites
*************

The big challenge for building examples for seventeen platforms
is installing seventeen cross-compiler toolchains.

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

Building
********

To build all examples, execute the following:

.. code-block:: bash

   cd smallworld/tests
   make -j $(nproc)
   ulimit -c unlimited
   make -C elf_core/Makefile

You can also build binaries for specific platforms using the following,
in case you only want a few programs, or if you only have a subset of the cross compilers:

.. code-block:: bash

   cd smallworld/tests
   make -j $PLATFORM

``$PLATFORM`` should be one of the following:

    - ``aarch64``: aarch64 assembly and ELF examples
    - ``amd64``: amd64 assembly and ELF examples
    - ``amd64_mingw``: amd64 PE examples, built using mingw
    - ``armel``: armv5t assembly and ELF examples
    - ``armhf``: armv7a assembly and ELF examples
    - ``i386``: x86 assembly and ELF examples
    - ``i386_mingw``: x86 PE examples, built using mingw
    - ``la64``: loongarch64 assembly and ELF examples
    - ``mips``: mips32r2 big endian assembly and ELF examples
    - ``mipsel``: mips32r2 little endian assembly and ELF examples
    - ``mips64``: mips64r2 big endian assembly and ELF examples
    - ``mips64el``: mips64r2 little endian assembly and ELF examples
    - ``ppc``: powerpc32 assembly and ELF examples
    - ``ppc64``: powerpc64 assembly and ELF examples
    - ``riscv64``: riscv64 assembly and ELF examples
    - ``xtensa``: xtensa assembly and ELF examples

.. warning::

   Not all compilers have the same names on different platforms.
   If your toolchain follows the Linux naming convention,
   you can override the variable ``${PLATFORM}_PREFIX``,
   where ``PLATFORM`` is the platform string in all caps.
   
