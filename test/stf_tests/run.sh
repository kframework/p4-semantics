#!/usr/bin/env bash

dir=$(dirname $0)
root="../.."

for i in $dir/test_data/*.k; do
    echo $i;
    n=${i%.*};
    time $root/script/kompile-semantics.sh $n.k --debug && time $root/script/run.sh $n.p4 --debug > $n.out;
done