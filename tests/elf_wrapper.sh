#!/bin/sh

as="$(basename $0 | sed 's/elfasm/as/')"
ld="$(basename $0 | sed 's/elfasm/ld/')"
tool_dir="$(dirname "$0")"
echo "as: $as"

out_file=$(echo "$@" | grep -oE -- '-femit-bin=\S+' | cut -d= -f 2)
tmp_file=${out_file%.elf}.o
args=$(echo "$@" | sed -E 's/-femit-bin=(\S+)\.elf/-o \1.o/')

# Bi-endian targets - SuperH is the one we have - need the endianness restated
# to the linker. `ld` takes its default from the target triple (sh4-unknown-
# linux-gnu is little-endian) and refuses a mismatched object with "compiled for
# a big endian system and target is little endian" rather than adapting to it.
# `objcopy -O binary` needs no such help, so the raw-binary path is unaffected.
ld_endian=""
case " $* " in
  *" -big "* | *" --big "*) ld_endian="-EB" ;;
  *" -little "* | *" --little "*) ld_endian="-EL" ;;
esac

echo "$as $args"
$as $args

if [ "$as" = "tricore-elf-as" ]; then
  linkerscript="$tool_dir/tricore_elf_linkerscript.ld"
  echo "$ld -T $linkerscript $tmp_file -o $out_file"
  $ld -T "$linkerscript" "$tmp_file" -o "$out_file"
else
  echo "$ld $ld_endian $tmp_file -o $out_file"
  $ld $ld_endian "$tmp_file" -o "$out_file"
fi
