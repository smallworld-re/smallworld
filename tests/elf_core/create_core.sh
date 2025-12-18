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
    sysroot=$AARCH64_SYSROOT
elif [ "$platform" = "amd64" ]; then
    sysroot=$AMD64_SYSROOT
    qemu_bin="qemu-x86_64"
elif [ "$platform" = "armel" ]; then
    echo "FIXME: No sysroot for arm32 in Nix"
    exit 0
elif [ "$platform" = "armhf" ]; then
    echo "FIXME: no sysroot for arm32 in nix"
    exit 0
elif [ "$platform" = "i386" ]; then
    echo "FIXME: no sysroot for i386 in nix"
    exit 0
elif [ "$platform" = "mips" ]; then
    echo "FIXME: QEMU can't run zig-compiled mips32 programs"
    exit 0
elif [ "$platform" = "mipsel" ]; then
    echo "FIXME: QEMU can't run zig-compiled mips32 programs"
    exit 0
elif [ "$platform" = "mips64" ]; then
    echo "FIXME: Something is horribly wrong with mips64 ld.so"
    exit 0
elif [ "$platform" = "mips64el" ]; then
    echo "FIXME: Something is horribly wrong with mips64 ld.so"
    exit 0
elif [ "$platform" = "ppc" ]; then
    sysroot=$PPC_SYSROOT
elif [ "$platform" = "ppc64" ]; then
    echo "FIXME: Something is horribly wrong with ppc64 ld.so"
    exit 0
fi


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
    gdb -batch-silent -ex "set logging file $1.registers" -ex "set logging enabled on" -ex "info registers" "$1" "$1.core"
else
    echo "ERROR: Core file not created for $1"
    exit 1 
fi
