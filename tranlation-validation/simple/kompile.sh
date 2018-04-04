#!/bin/bash -x
kompile --syntax-module P4-SYNTAX p4-semantics.k
kompile impp.k
kompile common.k
