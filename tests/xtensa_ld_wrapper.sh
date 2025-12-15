#!/bin/sh

out_file=$(echo $2 | cut -d '=' -f 2)
xtensa-lx106-elf-ld $1 -o $out_file
