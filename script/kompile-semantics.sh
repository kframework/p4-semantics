#!/usr/bin/env bash

dir=$(dirname $0);

if [ $# -lt 1 ]; then
    echo "usage: kompile-semantics.sh [<input-file> | --no-input] [kompile arguments]"
    exit 1
fi
DATA=$1
shift
if [ $DATA = "--no-input" ]; then
    DATA=""
else
    if [ ! -e $DATA ]; then
        echo "$DATA does not exist"
        exit 1
    fi
fi
python $dir/add-data.py $DATA
kompile $dir/../src/p4-semantics.k --syntax-module P4-SYNTAX --main-module P4-SEMANTICS $@