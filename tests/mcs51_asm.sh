#!/bin/sh
# Assemble an 8051 test with SDCC's tools, standing in for the
# `<assembler> <source> -femit-bin=<object>` step of the Makefile's assembly
# template.  The "object" written is already the raw binary, so the
# platform's objcopy step only copies it.
#
# Code goes in CSEG, linked at 0x1000, where the harness loads raw binaries;
# absolute jumps and `mov dptr, #label` then resolve to the right address.

src=""
out=""
for arg in "$@"; do
    case "$arg" in
        -femit-bin=*) out="${arg#-femit-bin=}" ;;
        *) src="$arg" ;;
    esac
done

if [ -z "$src" ] || [ -z "$out" ]; then
    echo "usage: $0 <source.s> -femit-bin=<output>" >&2
    exit 1
fi

tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT

cp "$src" "$tmp/prog.s"
echo "sdas8051 -plosgff $tmp/prog.s"
sdas8051 -plosgff "$tmp/prog.s" || exit $?
echo "sdld -i -b CSEG=0x1000 $tmp/prog.ihx $tmp/prog.rel"
sdld -i -b CSEG=0x1000 "$tmp/prog.ihx" "$tmp/prog.rel" || exit $?
echo "sdobjcopy -I ihex -O binary $tmp/prog.ihx $out"
sdobjcopy -I ihex -O binary "$tmp/prog.ihx" "$out"
