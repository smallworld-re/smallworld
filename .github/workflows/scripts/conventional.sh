#!/bin/bash

# Allowed subject characters: letters, digits, space, ( ) { }, backtick,
# slash, dot, comma, underscore and hyphen. The hyphen is intentionally last
# so it is treated literally rather than as a range operator: the previous
# ',-_' range accidentally matched the whole ASCII span 0x2C-0x5F (; : < = > ?
# @ [ \ ] ^). The count is written {0,62} for portability ({,62} is a GNU
# extension).
re='^(feat|fix|build|chore|ci|docs|style|refactor|perf|test): [A-Za-z0-9 (){}`/.,_-]{0,62}$'
if ! [[ "$1" =~ $re ]]; then
    echo "'$1' is not in conventional commit format"
    exit 1
fi
