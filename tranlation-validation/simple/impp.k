
module IMPP-SYNTAX
  syntax AExp  ::= Int | Id | Call
                 | AExp "/" AExp              [left, strict, klabel(divi)]
                 > AExp "+" AExp              [left, seqstrict, klabel(addi)]
                 | "(" AExp ")"               [bracket]
  syntax BExp  ::= Bool
                 | AExp "<=" AExp             [seqstrict, klabel(lei)]
                 | "!" BExp                   [strict]
                 > BExp "&&" BExp             [left, strict(1), klabel(andi)]
                 | "(" BExp ")"               [bracket]
  syntax Block ::= "{" "}"
                 | "{" Stmt "}"
  syntax Stmt  ::= Block
                 | Call ";" [strict(1)]
                 | Id "=" AExp ";"            [strict(2)]
                 | "if" "(" BExp ")"
                   Block "else" Block         [strict(1)]
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
  syntax Args ::= List{Arg,","} [strict,klabel('Args)]
  syntax Call ::= Id "(" Args ")"   [strict(2)]


endmodule

module IMPP
  imports IMPP-SYNTAX

  syntax Id ::= "main" [token]

  configuration <L2>
                  <k> $PGM:Pgm ~> main ( .Args ); </k>
                  <state> .Map </state>
                  <funs> .Map </funs>
                  <stack> .List </stack>
                </L2>


  syntax Val ::= Int | Bool
  syntax Vals ::= List{Val,","} [klabel('Vals)]
  syntax KResult ::= Val | Vals

  syntax AExp ::= Val
  syntax BExp ::= Val
  syntax Call ::= Val

  syntax Fun ::= "$fun" "(" Params "," Block ")"
  syntax Cnt ::= "$cnt" "(" Params "," K ")"

  syntax KItem ::= "@bind" "(" Vals "," Params ")"
  rule @bind (.Vals,.Params) => .K
  rule <k> @bind ((V:Val , Vs:Vals) => Vs , (Type P:Id , Ps:Params ) => Ps) ... </k> <state> (.Map => (P |-> V)) _:Map </state>

  syntax KItem ::= "@unbind" "(" Params ")"
  rule @unbind (.Params) => .K
  rule <k> @unbind ((Type P:Id , Ps:Params ) => Ps) ... </k> <state> M:Map => M[P <- undef] </state>

// AExp
  syntax Args ::= Vals
  rule .Args => .Vals
  rule <k> X:Id => I ...</k> <state>... X |-> I ...</state>
  rule  <k> F:Id (V:Vals) ~> C:K => @bind(V,P) ~> B ~> return; </k>
        <stack> (.List => ListItem($cnt(P,C))) _:List </stack>
        <funs> (F |-> $fun(P:Params,B:Block)) _:Map </funs>
        <state> S:Map </state>

  rule I1 / I2 => I1 /Int I2  requires I2 =/=Int 0
  rule I1 + I2 => I1 +Int I2
// BExp
  rule I1 <= I2 => I1 <=Int I2
  rule ! T => notBool T
  rule true && B => B
  rule false && _ => false
// Block
  rule {} => .   [structural]
  rule {S} => S  [structural]
// Stmt
  rule <k> X = I:Val; => . ...</k> <state>... X |-> (_ => I) ...</state>
  rule S1:Stmt S2:Stmt => S1 ~> S2  [structural]
  rule if (true)  S else _ => S
  rule if (false) _ else S => S
  rule while (B) S => if (B) {S while (B) S} else {}  [structural]

  rule return ; => return 0; [macro]
  rule <k> return V:Val ; ~> _ => @unbind(P) ~> V ~> C  </k>
       <stack> (ListItem($cnt(P:Params,C:K)) => .List) _:List </stack>
  rule _:Val ; => .K
// Pgm
  rule <k> int X ; => .K ... </k> <state> Rho:Map (.Map => X |-> 0) </state> requires notBool (X in keys(Rho))
  rule <k> bool X ; => .K ... </k> <state> Rho:Map (.Map => X|-> false) </state> requires notBool (X in keys(Rho))
  rule <k> _:Type F:Id (P:Params) B:Block => .K ... </k> <funs> Rho:Map (.Map => F|-> $fun(P,B)) </funs>  requires notBool (F in keys(Rho))

//Dec
  rule D:Dec Ds:Decs => D ~> Ds [structural]
  rule .Decs => .K              [structural]
endmodule
