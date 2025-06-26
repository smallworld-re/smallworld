#!/bin/sh

platform=`echo "$1" | cut -d. -f2-2`

qemu_bin="qemu-$platform"
sysroot="/usr/$platform-linux-gnu"

if [ "$platform" = "amd64" ]; then
    sysroot="/lib/x86_64-linux-gnu"
    qemu_bin="qemu-x86_64"
elif [ "$platform" = "armel" ]; then
    sysroot="/usr/arm-linux-gnueabi"
    qemu_bin="qemu-arm"
elif [ "$platform" = "armhf" ]; then
    sysroot="/usr/arm-linux-gnueabihf"
    qemu_bin="qemu-arm"
elif [ "$platform" = "i386" ]; then
    sysroot="/usr/i686-linux-gnu"
elif [ "$platform" = "mips64" ]; then
    sysroot="/usr/mips64-linux-gnuabi64"
elif [ "$platform" = "mips64el" ]; then
    sysroot="/usr/mips64el-linux-gnuabi64"
elif [ "$platform" = "ppc" ]; then
    sysroot="/usr/powerpc-linux-gnu"
elif [ "$platform" = "ppc64" ]; then
    sysroot="/usr/powerpc64-linux-gnu"
fi

echo "foobar" | "$qemu_bin" -L "$sysroot" "$1"

find . -name 'core.*' | xargs -I @ rm @
find . -name "qemu_$1*.core" | xargs -I @ mv @ "$1.core"

if [ -f "$1.core" ]; then
    rm "$1.registers"
    gdb-multiarch -batch-silent -ex "set logging file $1.registers" -ex "set logging enabled on" -ex "info registers" "$1" "$1.core"
fi
