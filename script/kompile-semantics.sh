#!/usr/bin/env bash

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
python script/add-data.py $DATA
kompile src/configuration.k --syntax-module P4-SYNTAX $@