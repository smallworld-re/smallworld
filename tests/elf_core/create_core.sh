#!/bin/sh

core_limit=`ulimit -c`
if [ "$core_limit" = 0 ]; then
    echo "ERROR: Core file creation disabled; please use 'ulimit -c' or similar to override"
    exit 1
fi

platform=`echo "$1" | cut -d. -f2-2`

qemu_bin="qemu-$platform"
sysroot="/usr/$platform-linux-gnu"

if [ "$platform" = "amd64" ]; then
    sysroot="/lib/x86_64-linux-gnu"
    qemu_bin="qemu-x86_64"
    library_path="/lib/x86_64-linux-gnu"
    export LD_LIBRARY_PATH="$library_path"
elif [ "$platform" = "armel" ]; then
    sysroot="/usr/arm-linux-gnueabi"
    qemu_bin="qemu-arm"
elif [ "$platform" = "armhf" ]; then
    sysroot="/usr/arm-linux-gnueabihf"
    qemu_bin="qemu-arm"
elif [ "$platform" = "i386" ]; then
    sysroot="/usr/i686-linux-gnu"
elif [ "$platform" = "mips64" ]; then
    sysroot="/nix/store/5czdjjxnb4xdp8276394jp26lgxcafqw-glibc-mips64-unknown-linux-gnuabi64-2.40-66"
elif [ "$platform" = "mips64el" ]; then
    sysroot="/nix/store/rv485ps0r9sasp4d28y2brjv7r9i931s-glibc-mips64el-unknown-linux-gnuabi64-2.40-66"
elif [ "$platform" = "ppc" ]; then
    sysroot="/nix/store/aw79r8rbw2hxsd5snhkgglkn8rhkqyri-glibc-powerpc-unknown-linux-gnu-2.40-66"
elif [ "$platform" = "ppc64" ]; then
    sysroot="/nix/store/mnqgddwqgv42xy32mcas50bsv55p5gld-glibc-powerpc64-unknown-linux-gnuabielfv2-2.40-66"
fi

echo "foobar" | "$qemu_bin" -L "$sysroot" "$1"
export LD_LIBRARY_PATH=""

find . -name 'core.*' | xargs -I @ rm @
find . -name "qemu_$1*.core" | xargs -I @ mv @ "$1.core"

if [ -f "$1.core" ]; then
    rm -f "$1.registers"
    gdb-multiarch -batch-silent -ex "set logging file $1.registers" -ex "set logging enabled on" -ex "info registers" "$1" "$1.core"
else
    echo "ERROR: Core file not created for $1"
    exit 1 
fi
