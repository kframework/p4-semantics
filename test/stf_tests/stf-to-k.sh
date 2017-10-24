#!/usr/bin/env bash

for i in ../programs/p4c-tests/p4_14_samples/*.json; do
    echo $i;
    n=${i%.*};
    python stf-to-k.py $n.json $n.stf $n.k $n.expected;
done
