#!/usr/bin/env bash
n=${1%.*}
p4c-bm2-ss --p4v 14 $n.p4 -o $n.json
