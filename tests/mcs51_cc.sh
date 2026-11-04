#!/bin/sh
# Compile an 8051 C test with SDCC into an Intel HEX image.
#
#   mcs51_cc.sh [--stack-auto] [--c99] <source.c> <output.ihx>
#
# --c99 builds one of the shared C99 library-model tests: c99/mcs51_sdcc.h
# is included ahead of the source, to stand in for what SDCC's library lacks,
# and SDCC's long long library is linked, which it leaves out by default.
#
# The image starts with SDCC's reset vector and startup code, which
# initializes memory and calls main.  The linker's map is written next to it,
# as <output>.map with the .ihx dropped, for Executable.from_ihex to look up
# symbols in: functions to hook, globals to check, and the static parameters
# of SDCC's default calling convention.

flags=""
if [ "$1" = "--stack-auto" ]; then
    flags="--stack-auto"
    shift
fi
if [ "$1" = "--c99" ]; then
    flags="$flags -Wp-include,$(cd "$(dirname "$0")" && pwd)/c99/mcs51_sdcc.h -l liblonglong.lib"
    shift
fi
src="$1"
out="$2"

if [ -z "$src" ] || [ -z "$out" ]; then
    echo "usage: $0 [--stack-auto] [--c99] <source.c> <output.ihx>" >&2
    exit 1
fi

tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT

cp "$src" "$tmp/prog.c"
echo "sdcc -mmcs51 $flags $tmp/prog.c -o $tmp/prog.ihx"
# shellcheck disable=SC2086
sdcc -mmcs51 $flags "$tmp/prog.c" -o "$tmp/prog.ihx" || exit $?
cp "$tmp/prog.ihx" "$out"
cp "$tmp/prog.map" "${out%.ihx}.map"
