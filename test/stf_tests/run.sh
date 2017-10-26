#!/usr/bin/env bash

for i in test_data/*.out; do
    echo $i;
    n=${i%.*};
    ../../script/kompile-semantics.sh $n.k --debug && ../../script/run.sh $n.p4 --debug > $n.out;
done