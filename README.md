# P4K: Formal Semantics of P4 in K

This is an ongoing attempt to give formal semantics to  [P4](http://p4.org/) language using K framework.

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
If the program is finished processing the input packet (when you see `<k> . </k>` in the configuration), the output packet can be seen in the `<packetout>` cell.
Instead of looking at the output packet which is a binary string and is hard to read, you can look at the final value of the fields (`<fieldVals>`) in the instances (`<instance>`).
Each value is of the form `@val(I,W,S)` where `I` is the decimal value, `W` is its width, and `S` indicates whether the value signed (`true`) or unsigned (`false`).
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


### Misc. 

#### Currently unsupported features

- Variable length header fields
- Saturating fields 
- Negative numbers
- Header stacks (array instances)
- Field lists
- Field lists calculations 
- Calculated fields (so the checksum of packets won't be verified or updated)
- Parser exceptions
- Value set declarations
- Counters, meters, and registers
- Action profiles
- Any matching type other than exact and valid (ternary, lpm, range)
- Any primitive action other than modify_field,subtract_from_field, and subtract 

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