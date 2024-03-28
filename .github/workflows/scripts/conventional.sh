#!/bin/bash

if ! [[ "$1" =~ ^(feat|fix|build|chore|ci|docs|style|refactor|perf|test):\ [A-Za-z0-9\ \(\)\{\}\`/.,-]{,62}$ ]]; then
    echo "'$1' is not in conventional commit format"
    exit 1
fi
