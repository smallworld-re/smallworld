#!/bin/sh

out_file=$(echo $5 | cut -d '=' -f 2)
tmp_file=$(echo $out_file | sed 's/\.elf/.o/')
xtensa-lx106-elf-as $1 $2 $3 $4 -o $tmp_file
xtensa-lx106-elf-ld $tmp_file -o $out_file
