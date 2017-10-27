#!/usr/bin/env bash

c=0;
p=0;
f=()
for i in test_data/*.out; do
    c=$((c+1));
    echo $i;
    n=${i%.*};
    python check_output.py $n.out $n.expected;
    if [ $? -eq 0 ]; then
        p=$((p+1));
    else
        f+=($n);
    fi;
done

echo "PASSED: $p / $c";
echo "FAILD: ${f[@]}";