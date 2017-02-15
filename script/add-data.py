#!/usr/bin/python

import sys

if len(sys.argv) < 2:
    data="//no input"
else:
    data=open(sys.argv[1],'r').read()
config=open('src/p4-semantics.k','r').read()
config = config.replace("#include_data",data)
open('src/configuration.k','w').write(config)


