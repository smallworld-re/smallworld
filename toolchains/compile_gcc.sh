#!/bin/bash

# Based off the tutorial at 
# https://preshing.com/20141119/how-to-build-a-gcc-cross-compiler/

# CLI parameters
TARGET="$1" # Target architecture ID
PREFIX="$2" # Directory prefix.  Defaults to ~/.local
if [ "$PREFIX" == "" ]; then
    PREFIX="$HOME/.local"
fi

# Derived parameters
ARCH=`echo "$TARGET" | cut -d'-' -f1-1`
if [ "$ARCH" == "loongarch32" ]; then
    ARCH="loongarch"
elif [ "$ARCH" == "loongarch64" ]; then
    ARCH="loongarch"
fi

# Extra arguments, passed via env
if [ "$BINUTILS_SRC" == "" ]; then
    BINUTILS_SRC="$PWD/binutils"
fi
if [ "$GCC_SRC" == "" ]; then
    GCC_SRC="$PWD/gcc"
fi
if [ "$LINUX_SRC" == "" ]; then
    LINUX_SRC="$PWD/linux"
fi
if [ "$GLIBC_SRC" == "" ]; then
    GLIBC_SRC="$PWD/glibc"
fi

# Also possible: 
#
# BINUTILS_EXTRA_ARGS
# GCC_EXTRA_ARGS
# GLIBC_EXTRA_ARGS

# Install odd dependencies
apt-get -y install build-essential bison flex libgmp3-dev libmpc-dev libmpfr-dev texinfo libisl-dev rsync gawk

# Clone all the repos.
if [[ ! -d "$BINUTILS_SRC" ]]; then
    echo "Cloning binutils to $BINUTILS_SRC"
    git clone https://github.com/bminor/binutils-gdb.git "$BINUTILS_SRC" || exit 1
fi
pushd "$BINUTILS_SRC" || exit 1
git checkout "binutils-2_45" || exit 1
popd || exit 1

if [[ ! -d "$GCC_SRC" ]]; then
    echo "Cloning gcc to $GCC_SRC"
    git clone https://github.com/gcc-mirror/gcc.git "$GCC_SRC" || exit 1
fi
pushd "$GCC_SRC" || exit 1
git checkout "basepoints/gcc-14" || exit 1
popd || exit 1

if [[ ! -d "$GLIBC_SRC" ]]; then
    echo "Cloning glibc to $GLIBC_SRC"
    git clone https://github.com/bminor/glibc.git "$GLIBC_SRC" || exit 1
fi
pushd "$GLIBC_SRC" || exit 1
git checkout "glibc-2.41" || exit 1
popd || exit 1

if [[ ! -d "$LINUX_SRC" ]]; then
    echo "Cloning linux kernel to $LINUX_SRC"
    git clone https://github.com/torvalds/linux.git "$LINUX_SRC" || exit 1
fi
pushd "$LINUX_SRC" || exit 1
git checkout "v6.16" || exit 1
popd || exit 1


export PATH="$PREFIX/bin:$PATH"

# Build binutils
echo "Building binutils"
rm -rf build-binutils || exit 1
mkdir build-binutils || exit 1
pushd build-binutils || exit 1

"$BINUTILS_SRC/configure" --prefix="$PREFIX" --target="$TARGET" --disable-multilib --with-sysroot --disable-werror --disable-nls --disable-gdb $BINUTILS_EXTRA_ARGS || exit 1
make -j $(nproc) || exit 1
make install-strip || exit 1

popd || exit 1

# Build GCC
echo "Building GCC"
rm -rf build-gcc || exit 1
mkdir build-gcc || exit 1
pushd build-gcc || exit 1

"$GCC_SRC/configure" --prefix="$PREFIX" --target="$TARGET" --enable-languages=c,c++ --disable-multilib --disable-nls $GCC_EXTRA_ARGS || exit 1
make -j $(nproc) all-gcc || exit 1
make install-strip-gcc || exit 1

popd || exit 1

exit 0

# Build Kernel Headers
echo "Building kernel headers"
pushd "$LINUX_SRC" || exit 1
make ARCH="$ARCH" INSTALL_HDR_PATH="$PREFIX/$TARGET" headers_install || exit 1
popd || exit 1

# Build glibc headers
echo "Building glibc headers"
rm -rf build-glibc || exit 1
mkdir build-glibc || exit 1
pushd build-glibc || exit 1

# NOTE: Weirdness with glibc; "host" and "target" both refer to $TARGET.
"$GLIBC_SRC/configure" --prefix="$PREFIX/$TARGET" --build=$MACHTYPE --host="$TARGET" --target="$TARGET" --with-headers="$PREFIX/$TARGET/include" --disable-multilib --disable-nls libc_cv_forced_unwind=yes $GLIBC_EXTRA_ARGS
make install-bootstrap-headers=yes install-headers || exit 1
make -j $(nproc) csu/subdir_lib || exit 1
install csu/crt1.o csu/crti.o csu/crtn.o "$PREFIX/$TARGET/lib" || exit 1
"$TARGET-gcc" -nostdlib -nostartfiles -shared -x c /dev/null -o "$PREFIX/$TARGET/lib/libc.so" || exit 1
touch "$PREFIX/$TARGET/include/gnu/stubs.h" || exit 1

popd || exit 1

# Build libgcc
echo "Building libgcc"
pushd build-gcc || exit 1

make -j $(nproc) all-target-libgcc || exit 1
make install-strip-target-libgcc || exit 1

popd || exit 1

# Build glibc
echo "Building glibc"
pushd build-glibc || exit 1

make -j $(nproc) || exit 1
make install || exit 1

popd || exit 1

# Build libstdc++
echo "Building libstdc++"
pushd build-gcc || exit 1

make -j $(nproc) all-target-libstdc++-v3 || exit 1
make install-target-libstdc++-v3 || exit 1

popd || exit 1
