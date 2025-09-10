# Cross-compiler Toolchain Build Environment

This directory contains the necessary environment
to build versions of GCC 14 that run on Ubuntu 22.04,
and which support architectures not normally
supported by Debian.

**WARNING:** This will NOT produce a real Ubuntu 22.04 build chain!

The script is configured to build a mash-up of the following:

- binutils 2.45
- GCC 14
- glibc 2.41
- Linux kernel 6.16

I make absolutely no guarantee that the resulting franken-compiler
will be compatible with any real-world system.
It's sufficient for building SmallWorld test artifacts.

## Contents

The following files are contained in this directory:

- `compile_gcc.sh`: Script for compiling the toolchain
- `buildtools-*`: Directories for configuring `.deb` files for the toolchains.

## Usage

Building a `.deb` file for a build chain works as follows:

```
# Assumes you're working in this directory

export TARGET= ...              # The target architecture triple
export BINUTILS_EXTRA_ARGS= ... # Any extra args needed to build binutils
export GCC_EXTRA_ARGS= ...      # Any extra args needed to build gcc
export GLIBC_EXTRA_ARGS= ...    # Any extra args needed to build glibc

./compile_gcc.sh "$TARGET" "$PWD/buildtools-$TARGET/usr"

dpkg --build "buildtools-$TARGET"
```

If you just want to build the cross-compiler,
you can omit the second argument, and `compile_gcc.sh`
will install the tools to `$HOME/.local`.

**WARNING:** `compile_gcc.sh` is INCREDIBLY messy!

It will clone the source for binutils, gcc, glibc,
and the Linux kernel into your current directory
(if they're not already there.)

It will also create build directories
for binutils, gcc, and glibc.

## Target Architectures

The following lists target triples that are tested,
and extra arguments found to make them work.

**NOTE:** `compile_gcc.sh` may need to be modified for new triples.

The kernel build system uses a different architecture ID system
from the rest of the tools.  The script attempts to translate,
but you may need to add cases where the mapping
just isn't obvious.

- `loongarch64-linux-gnu`:
    - `GLIBC_EXTRA_ARGS=--disable-default-pie`
