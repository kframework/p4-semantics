require "common.k"

module IMPP-SYNTAX
  syntax AExp  ::= Int | Id | Call
                 | AExp "/" AExp              [left, strict, klabel(divi)]
                 > AExp "+" AExp              [left, seqstrict, klabel(addi)]
                 | "(" AExp ")"               [bracket]
  syntax BExp  ::= Bool | Id | Call
                 | AExp "<=" AExp             [seqstrict, klabel(lei)]
                 | AExp "==" AExp             [seqstrict]
                 | "!" BExp                   [strict]
                 > BExp "&&" BExp             [left, strict(1), klabel(andi)]
                 | "(" BExp ")"               [bracket]
  syntax Block ::= "{" "}"
                 | "{" Stmt "}"
  syntax Stmt  ::= Block
                 | Call ";" [strict(1)]
                 | Id "=" Exp ";"            [strict(2)]
                 | "if" "(" BExp ")"
                   Block "else" Block         [strict(1)]
                 | "if" "(" BExp ")" Block    [prefer]
                 | "while" "(" BExp ")" Block
                 | "return" Exp ";"   [strict]
                 | "return" ";"
                 > Stmt Stmt                  [left]
  syntax Pgm ::= Decs

  syntax Dec ::= FunDec | VarDec
  syntax Decs ::= List{Dec,""} [klabel('Decs)]
  syntax VarDec ::= Type Id ";"
  syntax Type ::= "int" | "bool" | "void"
  syntax Param ::= Type Id
  syntax Params ::= List{Param,","} [klabel('Params)]
  syntax FunDec ::= Type Id "(" Params ")" Block

  syntax Exp ::= AExp | BExp
  syntax Arg ::= Exp
  syntax Args ::= List{Arg,","} [strict]
  syntax Call ::= Id "(" Args ")"   [strict(2)]

  // APIs
  syntax Id ::=  "#get_next_packet" [token]
                |"#output_packet" [token]
                |"#drop" [token]
                |"#emit" [token]
                |"#reset" [token]
                |"#call_entry_action" [token]
                |"#entry_matches" [token]
                |"#get_next_enrty" [token]
                |"#has_next" [token]
                |"#extract_next" [token]


endmodule

module IMPP
  imports IMPP-SYNTAX
  imports COMMON


  syntax Id ::= "main" [token]

  configuration <L2>
                  <k> $PGM:Pgm ~> main ( .Args ); </k>
                  <state> .Map </state>
                  <funs> .Map </funs>
                  <stack> .List </stack>
                  //API
                  <in> $nilPacketList </in>
                  <out> $nilPacketList </out>
                  <packet>  .List </packet>
                  <packetout> .List </packetout>
                  <table> .List </table>
                  <crntE> .List </crntE>
                  <index> 0 </index>
                </L2>


  syntax IVal ::= Int | Bool
  syntax IVals ::= List{IVal,","}
  syntax KResult ::= IVal | IVals

  syntax AExp ::= IVal
  syntax BExp ::= IVal
  syntax Call ::= IVal

  syntax Fun ::= "$fun" "(" Params "," Block ")"
  syntax Cnt ::= "$cnt" "(" Params "," K ")"

  syntax KItem ::= "@bind" "(" IVals "," Params ")"
  rule @bind (.IVals,.Params) => .K
  rule <k> @bind ((V:IVal , Vs:IVals) => Vs , (Type P:Id , Ps:Params ) => Ps) ... </k> <state> (.Map => (P |-> V)) _:Map </state>

  syntax KItem ::= "@unbind" "(" Params ")"
  rule @unbind (.Params) => .K
  rule <k> @unbind ((Type P:Id , Ps:Params ) => Ps) ... </k> <state> M:Map => M[P <- undef] </state>

// AExp
  syntax Args ::= IVals
  rule .Args => .IVals
  rule <k> X:Id => I ...</k> <state>... X |-> I ...</state>
  rule  <k> F:Id (V:IVals) ~> C:K => @bind(V,P) ~> B ~> return; </k>
        <stack> (.List => ListItem($cnt(P,C))) _:List </stack>
        <funs> (F |-> $fun(P:Params,B:Block)) _:Map </funs>
        <state> S:Map </state>

  rule I1 / I2 => I1 /Int I2  requires I2 =/=Int 0
  rule I1 + I2 => I1 +Int I2
// BExp
  rule I1 <= I2 => I1 <=Int I2
  rule I1 == I2 => I1 == I2
  rule ! T => notBool T
  rule true && B => B
  rule false && _ => false
// Block
  rule {} => .   [structural]
  rule {S} => S  [structural]
// Stmt
  rule <k> X = I:IVal; => . ...</k> <state>... X |-> (_ => I) ...</state>
  rule S1:Stmt S2:Stmt => S1 ~> S2  [structural]
  rule if (true)  S else _ => S
  rule if (false) _ else S => S
  rule if (B) Blk:Block => if (B) Blk else {}
  rule while (B) S => if (B) {S while (B) S} else {}  [structural]


  rule return ; => return 0; [macro]
  rule <k> return V:IVal ; ~> _ => @unbind(P) ~> V ~> C  </k>
       <stack> (ListItem($cnt(P:Params,C:K)) => .List) _:List </stack>
  rule _:IVal ; => .K
// Pgm
  rule <k> int X ; => .K ... </k> <state> Rho:Map (.Map => X |-> 0) </state> requires notBool (X in keys(Rho))
  rule <k> bool X ; => .K ... </k> <state> Rho:Map (.Map => X|-> false) </state> requires notBool (X in keys(Rho))
  rule <k> _:Type F:Id (P:Params) B:Block => .K ... </k> <funs> Rho:Map (.Map => F|-> $fun(P,B)) </funs>  requires notBool (F in keys(Rho))

//Dec
  rule D:Dec Ds:Decs => D ~> Ds [structural]
  rule .Decs => .K              [structural]



    // APIs

    rule <k> #reset (.IVals) => 0 ... </k>
         <index> _ => 0 </index>
         <crntE> _ => T </crntE>
         <table> T </table>
         <packetout> _ => .List </packetout>

    rule <k> #outputPacket (.IVals) => 0 ... </k>
         <packetout> P:List </packetout>
         <state> standard_metadata_egress_spec |-> I:Int _:Map </state>
         <out> L:PacketList => $consPacketList($packet(P,I), L) </out>
         when I =/=Int -1

    rule <k> #drop (.IVals) => 0 ... </k>

    rule <k> #emit (V:Int ,W:Int, S:Bool , .IVals) => 0 ... </k>
         <packetout> _:List (.List => ListItem(@val(V,W,S))) </packetout>

    rule <k> #get_next_packet (.IVals) => true ... </k>
         <in> $consPacketList($packet(P:List, _:Int), L:PacketList) => L </in>

    rule <k> #get_next_packet (.IVals) => false ... </k>
         <in> $nilPacketList </in>

    rule <k> #has_next (_:Int , .IVals) => true ... </k>
         <packet> L:List </packet>
         <index> I:Int </index>
         when I <Int sizeList(L)
    rule <k> #has_next (_:Int , .IVals) => false ... </k>
         <packet> L:List </packet>
         <index> I:Int </index>
         when I >=Int sizeList(L)

    rule <k> (.K =>L[I]) ~> #extract_next (W:Int,S:Bool, .IVals)  ... </k>
         <packet> L:List </packet>
         <index> I:Int => I +Int 1 </index>
    rule <k> @val(V:Int,W,S) ~> #extract_next (W:Int,S:Bool, .IVals) => V ... </k>


    rule <k> #get_next_enrty (.IVals) => false ... </k>
         <crntE> .List </crntE>
    rule <k> #get_next_enrty (.IVals) => true ... </k>
         <crntE> ListItem(_) _:List </crntE>


    rule <k> #entry_matches (I:Int , .IVals) => true ... </k>
         <crntE> ListItem($rule(_, $ctr(ListItem(@val(I,_,_))), _)) _:List </crntE>

    rule <k> #entry_matches (I:Int , .IVals) => false ... </k>
         <crntE> ListItem($rule(_, $ctr(ListItem(@val(J:Int,_,_))), _)) _:List </crntE>
      when I =/=Int J

    //rule <k> call_entry_action (.IVals) => A (#valList2IVals(L)) ... </k>
    //     <crntE> ListItem($rule(_, _, @call(A:Id, $resolved (L:List) ))) _:List </crntE>


    syntax KResult ::= Val | Vals

    syntax IVals ::= "#valList2IVals" "(" List ")" [function]
    rule #valList2IVals(.List) => .IVals
    rule #valList2IVals(ListItem(@val(I:Int,_,_)) L:List) => I , #valList2IVals(L)



    syntax Id ::= "standard_metadata_egress_spec" [token]


endmodule
