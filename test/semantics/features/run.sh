#!/usr/bin/env bash

dir=$(dirname $0)
root="../../.."

for i in $(find $dir -name "*.k"); do
    echo $i;
    n=${i%.*};
    time $root/script/kompile-semantics.sh $n.k --debug && time $root/script/run.sh $n.p4 --debug > $n.out;
done