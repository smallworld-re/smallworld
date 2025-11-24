#!/usr/bin/env bash

out_file=$(echo $2 | cut -d '=' -f 2)
nasm $1 -o $out_file
