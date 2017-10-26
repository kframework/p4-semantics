#!/usr/bin/env bash

for i in test_data/*.out; do
    echo $i;
    n=${i%.*};
    p4c-bm2-ss --p4v 14 $n.p4 -o $n.json;
done