
module SPEC
  imports TEST

  rule <k> V:Val => I:Int </k>
  //requires #noUndef(V)

  //rule <k> V:NUVal => I:Int </k>

endmodule
