#!/bin/sh

tool="$(basename $0 | sed 's/asm$/as/')"
args=$(echo "$@" | sed 's/-femit-bin=/-o /')

echo "$tool $args"
$tool $args
