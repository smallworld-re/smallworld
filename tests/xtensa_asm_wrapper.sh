#!/bin/sh

out_file=$(echo $5 | cut -d '=' -f 2)
xtensa-lx106-elf-as $1 $2 $3 $4 -o $out_file
