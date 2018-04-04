
module SPEC
  imports TEST


  rule <k> V:Val </k>
  //requires #noUndef(V)
  ensures vars(ListItem(V) ListItem(0))


  rule <k> I:Int </k>
  ensures vars(ListItem(I) ListItem(0))
  [trusted]

endmodule
