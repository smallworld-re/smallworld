#!/bin/sh

as="$(basename $0 | sed 's/elfasm/as/')"
ld="$(basename $0 | sed 's/elfasm/ld/')"
echo "as: $as"

out_file=$(echo "$@" | grep -oE -- '-femit-bin=\S+' | cut -d= -f 2)
tmp_file=${out_file%.elf}.o
args=$(echo "$@" | sed -E 's/-femit-bin=(\S+)\.elf/-o \1.o/')

echo "$as $args"
$as $args

echo "$ld $tmp_file -o $out_file"
$ld $tmp_file -o $out_file

