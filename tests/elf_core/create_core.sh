#!/bin/sh

core_limit=`ulimit -c`
if [ "$core_limit" = 0 ]; then
    echo "ERROR: Core file creation disabled; please use 'ulimit -c' or similar to override"
    exit 1
fi

platform=`echo "$1" | cut -d. -f2-2`

# Find our QEMU binary and our sysroot platform ID
qemu_bin="qemu-$platform"
if [ "$platform" = "aarch64" ]; then
    quad="aarch64-unknown-linux-gnu"
elif [ "$platform" = "amd64" ]; then
    quad=""
    qemu_bin="qemu-x86_64"
elif [ "$platform" = "armel" ]; then
    quad="arm-unknown-linux-gnueabi"
    qemu_bin="qemu-arm"
    echo "FIXME: No sysroot for arm32 in Nix"
    exit 0
elif [ "$platform" = "armhf" ]; then
    quad="arm-unknown-linux-gnueabihf"
    qemu_bin="qemu-arm"
    echo "FIXME: no sysroot for arm32 in nix"
    exit 0
elif [ "$platform" = "i386" ]; then
    quad="i686-unknown-linux-gnu"
    echo "FIXME: no sysroot for i386 in nix"
    exit 0
elif [ "$platform" = "mips" ]; then
    quad="mips-unknown-linux-gnueabihf"
    echo "FIXME: QEMU can't run zig-compiled mips32 programs"
    exit 0
elif [ "$platform" = "mipsel" ]; then
    quad="mipsel-unknown-linux-gnueabihf"
    echo "FIXME: QEMU can't run zig-compiled mips32 programs"
    exit 0
elif [ "$platform" = "mips64" ]; then
    quad="mips64-unknown-linux-gnuabi64"
    echo "FIXME: Something is horribly wrong with mips64 ld.so"
    exit 0
elif [ "$platform" = "mips64el" ]; then
    quad="mips64el-unknown-linux-gnuabi64"
    echo "FIXME: Something is horribly wrong with mips64 ld.so"
    exit 0
elif [ "$platform" = "ppc" ]; then
    quad="powerpc-unknown-linux-gnu"
elif [ "$platform" = "ppc64" ]; then
    quad="powerpc64-unknown-linux-gnuabielfv2"
    echo "FIXME: Something is horribly wrong with ppc64 ld.so"
    exit 0
fi

# Find the sysroot in the nix store 
sysroot=$(find /nix/store -maxdepth 2 -name "*glibc-$quad*-66" -type d | head -n 1)

if [ "$sysroot" = "" ]; then
    echo "ERROR: No sysroot for $platform"
    exit 1
fi
echo "$sysroot"

echo "foobar" | $qemu_bin -L "$sysroot" "$(realpath $1)"

find . -name 'core.*' | xargs -I @ rm @
find . -name "qemu_$1*.core" | xargs -I @ mv @ "$1.core"

if [ -f "$1.core" ]; then
    rm -f "$1.registers"
    gdb-multiarch -batch-silent -ex "set logging file $1.registers" -ex "set logging enabled on" -ex "info registers" "$1" "$1.core"
else
    echo "ERROR: Core file not created for $1"
    exit 1 
fi
