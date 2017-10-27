#!/usr/bin/python

import sys
import os
dir=os.path.dirname(sys.argv[0])
if len(sys.argv) < 2:
    data="//no input"
else:
    data=open(sys.argv[1],'r').read()
config=open(dir+'/../src/initialization-t.k','r').read()
config = config.replace("#include_data",data)
open(dir+'/../src/initialization.k','w').write(config)


