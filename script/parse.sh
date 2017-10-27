#!/usr/bin/env bash
dir=$(dirname $0)
kast -d $dir/../src/syntax/ $@
