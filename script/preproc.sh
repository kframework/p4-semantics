#!/usr/bin/env bash
gcc -E -x c -w $@ | grep -e "^#" -v
