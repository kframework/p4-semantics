#!/usr/bin/env bash

for i in ../programs/p4c-tests/p4_14_samples/*.out; do
    echo $i;
    n=${i%.*};
    python check_output.py $n.out $n.expected;
done