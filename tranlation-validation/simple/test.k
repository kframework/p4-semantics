//require "c.k"

module TEST
    //imports C

    syntax Val ::= "@undef" [smtlib(val_undef)]
    syntax Val ::= "@val" "("Int","Int","Bool")" [smtlib(smt_val)] //int,width,signed

    //syntax Val ::= NUVal
    //syntax NUVal ::=  "@val" "("Int","Int","Bool")"


    //=========
    //syntax Bool ::= vars(List)
    //========


    configuration
    <T>
        <k> $PGM:Val </k>
    </T>


    rule <k> @val(I:Int,_,_) => I </k>


    syntax Bool ::= "#noUndef" "(" Val ")" [function]//[function, smtlib(no_undef)]
    rule #noUndef(@val(_,_,_)) => true //[smt-lemma]
    rule #noUndef(@undef) => false     //[smt-lemma]
endmodule