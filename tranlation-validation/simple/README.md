To run KEQ:
```
    ./kompile.sh
    ./keq.sh
```

Note 1: Although the sync points are correct, K has several bugs that prevent the proof from going through normally:
- https://github.com/kframework/k-legacy/issues/2408
- https://github.com/kframework/k-legacy/issues/2409
- https://github.com/kframework/k-legacy/issues/2407
- The Z3 library that is used returns results different from what the latest version of Z3 returns.
More importantly its result is non-deterministic.
For example, in P4, starting from sync point p1 (`@getNextPacket`) and a symbolic input packet stream, there
are two possible next steps (`@end` parser if input stream is `@nil` and `@resetPerPacketState` otherwise).
However, sometimes K only reaches one of them. The reason is that the Z3 library used by K sometimes returns
`unsat` instead of `unknown` (this happens if `mbqi` is enabled, but it is explicitly disabled by the prelude file, so
this shouldn't happen). The very same query using the latest version of Z3 returns `unknown`.
- etc.

The `p4k-hacks` branch in the K framework repository addresses some of these problems, but not all.
Specially the problems with non-deterministic results are not resolved yet.
As a result, running `keq.sh` from command line most likely returns false.
What I personally do is that I use IntelliJ's debugger to run K in `keq` mode with the arguments given in `keq.sh`, set
a breakpoints in `EquivChecker.getNextSyncNodes`, and run step by step (specially around nondeterministic points
such as `@getNextPacket`). Surprisingly, it works this way!


Note 2: In P4 semantics, I set `%DROP_PORT` = -1 (= `#egreesVal2Int(@undef)`). In IMPP, -1 is used to represent
parsing error, undef egress, and drop port.
We could alternatively change the semantics of IMPP to use `%DROP_PORT` (a constant of sort Int) to represent the drop port.
In either case, it is important to note that the equivalence holds only if both semantics use the same drop port number.

Note 3: Syncpoint `p?` is only needed for the particular way the packet are implemented in our semantics, because we currently
have a loop over input packet payload in order to add it the output packet.
This was not necessarily needed if the implementation was different.
