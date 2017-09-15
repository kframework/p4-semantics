# P4K: Formal Semantics of P4 in K

This is an ongoing attempt to give **complete** formal semantics to the [P4](http://p4.org/) language (version 1.0.4)  using the K framework.
Based on this semantics, K provides various tools for the language, including an interpreter, a symbolic execution engine, etc ... 

## Using P4K:

At the current moment, only the syntax of P4 is fully developed.
The semantics of P4 is under development and is partial (see the last section)

### Dependencies:
- JRE 8
- K Framework
  + make sure the executables (kompile, kast, krun) are on PATH.
- GCC
  + only needed for preprocessing p4 source files

### Running simple P4 programs

As mentioned, the semantics is not fully developed yet. 
However, you can run very simple P4 program with the current partial semantics. 

In order to run a simple P4 program, you should first compile (kompile) the P4 language definition using K.
At the current moment, the table entries and the input packet need to be hard-coded inside the semantics.
So one needs to provide these inputs during kompilation. 

Get the latest commit from master branch and run:
```
  cd p4k/
  script/kompile-semantics.sh path/to/input/file.k
```

Where `path/to/input/file.k` is the input file containing the hard coded table entries and input packet.
See (`test/semantics/basic_routing/input1.k`) for an example of such input. 
If you do not want to add any inputs use `--no-input` instead of the input file.

Example:
```
  script/kompile-semantics.sh test/semantics/basic_routing/input1.k
```

After kompilation, in order to run P4 programs, run:

```
  script/run.sh path/to/source.p4
```

If your code contains preprocessing directives (e.g include, define, etc), you first need to preprocess it:
```
  script/preproc.sh path/to/source.p4 > some_file.p4
```

And then feed the output file into the `run.sh` script.

Example:

```
  script/run.sh test/semantics/basic_routing/basic_routing.p4
  <T> <k> ... 
```


The program will run until it is finished processing the input packet or it reaches a point where the semantics is not defined yet and will get stuck there.
In either case, the configuration of the program in its last state will be printed.
If the program is finished processing the input packet (when you see `<k> @nextPacket </k>` in the configuration), the output packet can be seen in the output buffer (`<out>` cell).
Instead of looking at the output packet which is hard to read, you can look at the final value of the fields (`<fieldVals>`) in the instances (`<instance>`).
Each value is of the form `@val(I,W,S)` where `I` is the decimal value, `W` is its width, and `S` indicates whether the value is signed (`true`) or unsigned (`false`).
If it is hard to read the configuration the way it is printed, you can put the output in an `.xml` file and view it in a browser.
 
If you want to see the computation step by step, you can run the program in the debug (`--debugger`) mode and use `step` to step and `peak` to see the configuration in each step.

Example:

```
  script/run.sh test/semantics/basic_routing/basics_routing.p4 --debugger
  KDebug> step
  1 Step(s) Taken.
  KDebug> peek
  <T> <k> ...
  KDebug> step 10
  10 Step(s) Taken.
```


### Symbolic Execution 

You can also run programs in symbolic mode, in which the inputs or parts of the input can be symbolic. To run the programs in symbolic mode, you first need to specify what is symbolic. Take a look 
at `test/semantics/basic_routing/sym-packet-input1.k` for an example of a symbolic input. In that example, the entire input packet is defined to be symbolic rather than concrete. 
Same as before, you need to kompile this input with the semantics.

And then you need to run your program in `search` mode:

```
 script/run.sh path/to/source.p4 --search
```

K will explore different paths and at the end of each path, it prints the final state and the path conditions.
If you want to to search whether the program can reach specific patterns you can provide the pattern using `--pattern` options (refer to K tutorials for more information on that).

Example:

```
 script/kompile-semantics.sh test/semantics/basic_routing/sym-packet-input1.k
 script/run.sh test/semantics/basic_routing/basics_routing.p4 --search 2> /dev/null
 Solution 1
 <T> <k>  ...
 AND V2 == 2048 ==k false andBool ...
 Solution 2
 .
 .
 .
```


Note: Currently there seems to be a problem with the latest release of K that prevents symbolic execution using this semantics.
I have made some minor hacks to K to have a temporary fix for the problem.
Because of that, if you want run P4 programs in symbolic mode, you should check out [this branch](https://github.com/kframework/k/tree/p4k-hacks) of K and build it.  


### Semantic Coverage Measurement

You can use the interpreter to check what percentages of the semantic rules are covered by the tests that you run. There is only a proof of concept available at the current moment.
You can take a look at the `coverage` directory for that. For example, to measure coverage for `basic_routing example`, do as follows:

```
 script/run.sh test/semantics/basic_routing/basic_routing.p4 2>&1 | grep "p4-semantics.k" > coverage/covered
 cd coverage
 ./extractRules.sh ../src/p4-semantics.k  > rules
 python produceReport.py
 ...
 ___________________________________stats___________________________________
 covered:	98 ( 60.87 %)
 uncovered:	63
 total:		161
```

Note: Similar to symbolic execution, for semantic coverage measurement, due to some minor problems in the latest version of K, you should checkout [this branch](https://github.com/kframework/k/tree/p4k-hacks) of K and build it.  


### Dataplane Verification

Instead of running just a simple P4 program, you can run a network of P4 programs. For that a simple semantics of network of P4 nodes is provided. 
The work is still under development, but you can check the `network-verification` directory if you are eager about it. 
Basically you need to provide an input program that contains all the P4 programs that are intended for the nodes in the network, separated by `----`. 
The first program goes to the first node, second program to second node, and so on ...
Take a look at `network-verification/basic_routingX3.p4` as an example. 
Then you need to hardcode the topology, input tables, and input packets (look at `network-verification/network-configuration.k` for more info -- though it is not very clean at the current moment).
And then kompile the semantics and then run the input program with it. 


### Misc. 

#### Currently unsupported features

- ~~Variable length header fields~~ (now supported)
- Saturating fields 
- Signed numbers (partly supported)
- Header stacks (array instances)
- ~~Field lists~~
- ~~Field lists calculations~~ 
- ~~Calculated fields (so the checksum of packets won't be verified or updated)~~
- Parser exceptions
- Value set declarations
- ~~~Counters, meters, and registers~~
- ~~Action profiles~~
- ~~Any matching type other than exact and valid (ternary, lpm, range)~~
- Any primitive action other than modify_field,add/subtract_from_field, and add/subtract 

#### Parsing P4 programs into KAST 

The syntax of P4 is fully developed. 
If you want to test the syntax only, you can parse P4 programs into KAST (K's AST) without running the programs.
 
You first need to compile (kompile) the P4 syntax definition using K. 
In order to do so get the source code ([this release](https://github.com/kframework/p4-semantics/releases/tag/parser)) and run:
```
  cd p4k/
  script/kompile-syntax.sh
```
Important Note: do not use the code on master branch. 

In order to parse P4 programs run:

```
  script/parse.sh path/to/source.p4
```


Example:

```
  script/parse.sh test/syntax/unit/mtag-edge-program.p4
  `'P4Declarations`(`header_type_{_}`(#token("ethernet_t","Id@ID"),...
```

### Questions/Problems?

Contact [Ali Kheradmand](kheradm2@illinois.edu) 