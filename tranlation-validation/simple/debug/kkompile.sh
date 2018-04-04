#!/bin/bash -x
kompile --syntax-module P4-SYNTAX p4-semantics.k
kompile imppp.k
kompile common.k
