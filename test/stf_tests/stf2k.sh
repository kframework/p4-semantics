#!/usr/bin/env bash

for i in test_data/*.json; do
    echo $i;
    n=${i%.*};
    python stf2k.py $n.json $n.stf $n.k $n.expected;
done
