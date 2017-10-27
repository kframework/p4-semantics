#!/usr/bin/env bash
dir=$(dirname $0)
rm -rf $dir/../src/syntax/p4-kompiled/
kompile $dir/../src/syntax/p4.k
