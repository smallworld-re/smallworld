#!/bin/sh

as="$(basename $0 | sed 's/elfasm/as/')"
ld="$(basename $0 | sed 's/elfasm/ld/')"
tool_dir="$(dirname "$0")"
echo "as: $as"

out_file=$(echo "$@" | grep -oE -- '-femit-bin=\S+' | cut -d= -f 2)
tmp_file=${out_file%.elf}.o
args=$(echo "$@" | sed -E 's/-femit-bin=(\S+)\.elf/-o \1.o/')

echo "$as $args"
$as $args

if [ "$as" = "tricore-elf-as" ]; then
  linkerscript="$tool_dir/tricore_elf_linkerscript.ld"
  echo "$ld -T $linkerscript $tmp_file -o $out_file"
  $ld -T "$linkerscript" "$tmp_file" -o "$out_file"
else
  echo "$ld $tmp_file -o $out_file"
  $ld "$tmp_file" -o "$out_file"
fi
