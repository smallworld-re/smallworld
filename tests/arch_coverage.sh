#!/bin/bash

platforms="aarch64 amd64 armel armhf mips mipsel mips64 mips64el ppc ppc64 riscv64 sparc64"
find_files() {
    local ext="$1"
    local stem="$2"
    printf "  %-10s " ".$ext:"
    for p in $platforms; do
        local platform_file="$stem.$p.$ext"
        
        local res="$p"
        if [[ ! -f "$platform_file" ]]; then
            local res=`echo "$res" | tr "[:alnum:]" " "`
        fi
        echo -n "$res "
    done
    echo ""
}

tests=`find . -name '*.s' | xargs -I @ basename @ | grep -oE '^[^.]+' | sort | uniq`
for t in $tests; do
    echo "$t:"
    find_files "s" "$t"
    find_files "py" "$t"
    find_files "angr.py" "$t"
done

