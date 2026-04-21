#!/bin/sh

wrapper="$(basename "$0")"
tool="$(printf '%s' "$wrapper" | sed 's/asm$/as/')"
linker="$(printf '%s' "$wrapper" | sed 's/asm$/ld/')"

args=""
out_file=""
for arg in "$@"; do
    case "$arg" in
        -femit-bin=*)
            out_file="${arg#-femit-bin=}"
            args="$args -o $out_file"
            ;;
        *)
            args="$args $arg"
            ;;
    esac
done

if [ "$wrapper" = "tricore-elf-asm" ]; then
    tmp_obj="${out_file}.tmp"
    asm_args=$(printf '%s' "$args" | sed "s| -o $out_file| -o $tmp_obj|")

    echo "$tool$asm_args"
    $tool $asm_args || exit $?

    echo "$linker -T ./tricore_linkerscript.ld -o $out_file $tmp_obj"
    $linker -T ./tricore_linkerscript.ld -o "$out_file" "$tmp_obj" || {
        rm -f "$tmp_obj"
        exit $?
    }
    rm "$tmp_obj"
    exit 0
fi

echo "$tool$args"
$tool $args
