# P4K: Formal Semantics of P4 in K

This is an ongoing attempt to give formal semantics to  [P4](http://p4.org/) language using K framework.

## Using P4K:

At the current moment, only the syntax of P4 is fully developed.
The semantics of P4 is under development and is partial. 

### Dependencies:
- JRE 8
- K Framework
  + make sure the executables (kompile, kast, krun) are on PATH.
- GCC
  + only needed for preprocessing p4 source files

### Running simple P4 programs

As mentioned, the semantics is not fully developed yet. 
However, you can run very simple P4 program with the current partial semantics. 
The program will run until it reaches a point where the semantics is not defined yet and will get stuck there.
Also note that a packet (and a simple rule) are currently hard-coded in the semantics. 

In order to run a simple P4 program, you should first compile (kompile) the P4 language definition using K. 
Get the lasest commit from master branch and run:
```
  cd p4k/
  script/kompile-semantics.sh
```

In order to run (simple) P4 programs run:

```
  script/run.sh path/to/source.p4
```

Example:

```
  script/run.sh test/semantics/test1.p4
  <T> <k> ... 
```


### Parsing P4 programs into KAST 

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

If your code contains preprocessing directives (e.g include, define, etc), you first need to preprocess it:
```
  script/preproc.sh path/to/source.p4 > some_file.p4
```

And then feed the output file into the parser.

Example:

```
  script/parse.sh test/syntax/unit/mtag-edge-program.p4
  `'P4Declarations`(`header_type_{_}`(#token("ethernet_t","Id@ID"),...
```

### Questions/Problems?

Contact [Ali Kheradmand](kheradm2@illinois.edu) 