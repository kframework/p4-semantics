# P4K: Formal Semantics of P4 in K

P4K aims at providing **complete** formal semantics for the [P4](http://p4.org/) language (currently P4_14 v. 1.0.4)  using the K framework.
Based on this semantics, K provides various tools for the language, including an interpreter, a symbolic execution engine and model checker, a deductive program verifier, a cross-language program equivalence checker, etc ...

For a high level overview of P4K and its applications you can checkout the following resources:
- A Formal Semantics of P4 and Applications, [M.Sc. Thesis](https://www.ideals.illinois.edu/handle/2142/102486) 
- P4K: A Formal Semantics of P4 and Applications, [arXiv draft](https://arxiv.org/abs/1804.01468)
- Executable Formal Semantics of P4 and Applications, [P4 Workshop 2017](https://p4.org/assets/p4-ws-2017-p4k-executable-formal-semantic.pdf)   

## Using P4K:
 

### Dependencies:
- K Framework (version 4)
  + Checkout the `p4k-hacks` branch from K's repository. The branch contains a few bug fixes, edits, and additions necessary for this project.
    - UPDATE: The project is being ported to the latest version of K (version 5). Part of the functionality (e.g. the interpreter) currently works with the latest version.  
  + Make sure the executables (kompile, kast, krun) are on PATH.
- GCC
  + Only needed for preprocessing p4 source files

### Running P4 programs

K automatically derives an interpreter for the P4 language directly from our semantics.
The interpreter can be used to execute and test P4 programs (this is especially useful for making sure that the semantics is correct).  
In order to run a P4 program, you should first compile (`kompile`) our language definition using K.
The current preferred method to provide input (packets, table entries, etc) for a P4 program is to do it statically (the input will be hard-coded in the semantics).
Such input is provided to the program under execution during the "initialization phase" ([more info]((https://arxiv.org/abs/1804.01468))) of the execution. 
In order to `kompile` the language definition with a static input run:
```
  cd p4k/
  script/kompile-semantics.sh path/to/input/file.k
```

Where `path/to/input/file.k` is the input file containing the hard coded table entries and the input packet(s).
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


The program will run until it is finished processing all packets in the input packet stream or it reaches a point where the semantics is not defined yet (due to problems in the language specification) and will get stuck there.
In either case, the configuration of the program in its last state will be printed.
If the program is finished processing the input packet stream (when you see `<k> @nextPacket </k>` and `<in> . </in>` in the configuration), the output packet stream can be seen from the output buffer (the `<out>` cell).
You may also inspect other parts of the configuration. For example you can view the final value of the fields for the last packet (the `<fieldVals>` cell) in the instances (the `<instance>` cell).
Each value is of the form `@val(I,W,S)` where `I` is the decimal value, `W` is its width, and `S` indicates whether the value is signed (`true`) or unsigned (`false`) (I might replace this with fix width bitvectors in the near future, but it is more human readable in the current form)
If it is hard to read the configuration you may use a XML formatter. My preference is to save the output in with `.xml` extension and view it in a browser).
 
If you want to see the computation step by step, you can run the program in the debug (`--debugger`) mode and use `step`/`s` to step, `backstep`/`b` to step back and `peak`/`p` to see the configuration in each step, 

Example:

```
  script/run.sh test/semantics/basic_routing/basics_routing.p4 --debugger
  KDebug> step
  1 Step(s) Taken.
  KDebug> peek
  <T> <k> ...
  KDebug> step 10
  10 Step(s) Taken.
  KDebug> peek
  <T> <k> ...
  KDebug> b 2
  KDebug> peek
  <T> <k> ...
```


### Symbolic Execution 

You can also run programs in symbolic mode, in which parts of the configuration (e.g, the input packets or parts of an input packet, tables, or pretty much anything else) can be symbolic. 
To run the programs in symbolic mode, you first need to specify what is symbolic. 
Take a look  at `test/semantics/basic_routing/sym-packet-input1.k` for an example of a symbolic input. 
In that example, the entire content of a single input packet is defined to be symbolic rather than concrete. 
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

### Dataplane Verification

Instead of running just a single P4 program, you can run a network of P4 programs.
More importantly, by use of symbolic execution, you can do the kind of analysis that other data plane verification tools (such as HSA, Veriflow, Delta-net, etc) do.
For example, given a snapshot of the data plane, let's say you are interested in knowing what kind of packets can reach node A from node B. 
In order to find the answer, you may inject a symbolic packet and not A and use symbolic execution to find the constraints on the symbolic packets that reach node B.
 
In order to run and analyse networks, a simple semantics of a network of P4 nodes is provided. 
The work is still under development, but you can check the `network-verification` directory for more details. 
Basically you need to provide an input program that contains all the P4 programs that are intended for the nodes in the network, separated by `----`. 
The first program goes to the first node, second program to second node, and so on ...
Take a look at `network-verification/basic_routingX3.p4` as an example. 
Then you need to hardcode the topology, input tables, and input packets (look at `network-verification/network-configuration.k` for more info -- though it is not very clean at the current moment).
And then kompile the semantics and then run the input program with it.


### Program Verification

K features a language independent program verification infrastructure based on [Reachability Logic](http://dx.doi.org/10.1145/2983990.2984027);
It can be instantiated with the semantics of a programming language such as P4 to automatically provide a sound and relatively complete program verifier for the language.
This eliminates the need for development of an additional semantics for verification of complex properties about P4 programs and networks.
In this system, properties to be verified are given using a set of reachability assertions.
The standard pre/post conditions and loop invariants used in Hoare style program verification can be encoded as reachability assertions.

There is an example in the `verification/load-balancer` directory that illustrates the the use of K's deductive verifier to prove a property about a simple P4 program.
The program features a very simple load balancer that balances the input packets from all of its ports between two output ports. 
We try to prove that program (along with its table inputs) correctly balances the load: 
"For any input stream of packets, after processing all the packets, no packet is dropped and no new packet is added; all the packets in the output are either sent to port 0 or port 1; and the absolute difference between the number of packets sent to ports 0 and 1 is less than or equal to 1".
`load-balancer.p4` contains the load balancer program; 
`tables.k` contains the table entries;
and `size_balance_spec.k` contains the property to be proved in expressed in form of a reachability assertion (`rule [spec]`). 
It also contains a loop invariant that is necessary for the verification (`rule [loop-inv]`).
`list.smt2` contains a few Z3 declarations and axioms that are necessary for the proof to go through (not all of it is needed thought).
More information on the program, the entries, the property, and the invariant can be found [here](https://arxiv.org/abs/1804.01468).
In order to run the program verifier, run `prove.sh`. `true` means that the property is proved. 

### Translation Validation

Recently, K has introduced a prototype tool for cross language program equivalence check using a generalized notion of bisimulation.
The tool takes K semantics of two programming languages and two input programs written in the
respective languages as input and and checks whether or not the two programs are equivalent.
In doing so, the tool usually needs a few hints from the translator. 
The hints are provided in form of synchronization points. 
Each synchronization point is a pair of symbolic states in the two input programs that are supposed to correspond to each other. 

To illustrate the use of the tool, we developed a simple C-like language (called IMP+) and its semantics using K.
We then manually translated an example P4 program into IMP+ and used the equivalence checker tool to establish the equivalence. 
Our goal was to prove that: starting from any input stream of packets and any table entries, the two programs will generate the same output stream of packets according to their semantics.  
`impp.k` contains the semantics of IMP+. `
simple.p4` and `simple.imp` are the example P4 program and its translation to IMP+, respectively.
`p4-spec.k` and `impp-spec.k` contain the respective synchronization points in the P4 and the IMP+ programs.
More information on the synchronization points can be found [here](https://arxiv.org/abs/1804.01468). 
Please refer to `README.md` in that directory for more information regarding running the equivalence checker. 
   

### Semantic Coverage Measurement

You can use the interpreter to check what percentages of the semantic rules are covered by the tests that you run. 
You can take a look at the `coverage` directory for that. 
For example, to measure coverage for `basic_routing example`, do as follows:

```
 script/run.sh test/semantics/basic_routing/basic_routing.p4 2>&1 | grep "p4-semantics.k" > coverage/covered
 cd coverage
 ./extractRules.sh ../src/p4-semantics.k  > rules
 python produceReport.py
 ...
```


### Misc. 

#### Limitations
The following features are partially supported:
- Saturating and signed fields/numbers
- Expressions containing numbers with different widths
- Overflows

Also the ingress and egress pipelines are currently modeled together as a single thread.
So the buffering mechanism can only contain a single packet at a time.
As a result, the support for cloning a packet into ingress is a bit hacky.   
  

#### Language Design/Specification Issues

We have encountered with several language design issues and corner cases in the specification of P4_14. 
The file `issues.txt` contains some of the issues. 
I have reported some of the issues to the P4 language specification's repository.
You may find them [here](https://github.com/p4lang/p4-spec/issues?utf8=%E2%9C%93&q=author%3Akheradmand).

#### Multi-threading (work in progress)

Real world high performance packet processors usually have multiple threads of execution. 
Although the specification is silent about the concurrency model,
there is a work in progress in the `multithreaded` directory to provide semantics of multi-threading inside P4 programs.
Using the K's model checker (i.e the `search` mode), one can explore the state space of concurrent P4 programs and for example check for possible outputs when there is a data races over stateful registers that affects the output (`race.p4` is such an example).
Even using single threaded programs, it is possible to check the state space of interaction of multiple P4 programs in a network. 

  
#### Parsing P4 programs into KAST 

If you want to test the syntax only, you can parse P4 programs into KAST (K's AST) without running them.
 
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
