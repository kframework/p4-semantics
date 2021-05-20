require "../p4/p4-semantics.k"
require "../cli/cli-symbolic.k"

module P4ASSERT-COMMON
imports P4-COMMON
    syntax Assertion ::= "@assert" "[" Id "]" BoolExpr ";"
    syntax ControlStatement ::= Assertion
    syntax ActionStatement ::= Assertion

    syntax AssertExpr ::=
                          "#isReached"
                        | "#isConstant"  "(" FieldRef ")"
                        | "#isDeparsed"  "(" HeaderRef ")"
                        | "#isValid"     "(" HeaderRef ")"
                        | "#isForwarded"
                        | "#isDropped"
                        | "#isUndef" "(" FieldRef ")"

    syntax BoolExpr ::= AssertExpr


   // need to pre-process due to thing like #isReached
endmodule

module P4ASSERT-SYNTAX
imports P4ASSERT-COMMON
imports P4-SYNTAX
imports CLI-SYMBOLIC-SYNTAX

endmodule

module P4ASSERT-SEMANTICS
imports P4ASSERT-COMMON
imports P4-SEMANTICS
imports DOMAINS
imports CLI-SYMBOLIC-SEMANTICS

    configuration
        //<p4/>
        //<p4pgm> @loadP4Program($PGM:P4Program) ~> .K </p4pgm>
        <CLI/>
        <p4assert>
            <assertions>
                <assertion multiplicity="*" type="Set">
                    <assertId> .K </assertId>
                    <result> .K </result>
                    <forwarded> .K </forwarded>
                </assertion>
            </assertions>
            <evalMode> NO_EVAL </evalMode>
        </p4assert>

    syntax EvalMode ::= "FINAL_EVAL" | "PARTIAL_EVAL" | "NO_EVAL"

//    syntax KItem ::= "@loadP4Program" "(" P4Program ")"
//    rule <p4pgm> @loadP4Program(Program:P4Program) => .K </p4pgm>
//         <p4> <k> _ => @runP4Program(Program) </k> ... </p4>

    // -------------------- pre-processing ----------------------

    rule <k> @processDec(action Name:ActionName ( Params:ParamList ) { Body:ActionStatements }  )
             => @processAssert(Body) ...
         </k>
         <actions> (.Bag =>
              <action>
                <a-name> Name </a-name>
                <params> Params </params>
                <a-body> Body </a-body>
                ...
              </action>)
              ...
         </actions>
         [priority(49)] //higher priority than normal rules (50)

    rule <k>
            @processDec(control Name:ControlFunctionName { Body:ControlStatements } )
            => @processAssert(Body) ...
         </k>
         <controlFlows> (.Bag =>
                   <control>
                        <c-name> Name </c-name>
                        <c-body> Body </c-body>
                        ...
                   </control>)
                   ...
         </controlFlows>
         <cfset> (.Set => SetItem(Name)) _ </cfset>
         [priority(49)] //higher priority than normal rules (50)

    syntax AssertPositions ::= ActionStatements | ControlStatements | CaseList
    syntax KItem ::= "@processAssert" "(" AssertPositions ")"

    rule     @processAssert( .ActionStatements) => .K
    rule     @processAssert( _ ( _ );  R:ActionStatements => R)
    rule     @processAssert(.ActionCases) => .K
    rule     @processAssert(.HitMissCases) => .K
    rule     @processAssert(.ControlStatements) => .K
    rule     @processAssert(_ ( );  R:ControlStatements => R)
    rule     @processAssert(apply ( _ ); R:ControlStatements => R)
    rule     @processAssert(apply ( _ ) {C:CaseList} R:ControlStatements => R)
                ~> (.K => @processAssert(C))
    rule     @processAssert(_ { C:ControlStatements } R:ActionCases => R)
                ~> (.K => @processAssert(C))
    rule     @processAssert(_ { C:ControlStatements } R:HitMissCases => R)
                ~> (.K => @processAssert(C))
    rule     @processAssert(if (_) { C:ControlStatements } R:ControlStatements => R)
                ~> (.K => @processAssert(C))
//    rule     @processAssert(if (_) { CT:ControlStatements } else { CF:ControlStatements} R:ControlStatements => R)
//                ~> (.K => @processAssert(CT) ~> @processAssert(CF))
    rule  @processAssert(if (_) { CT:ControlStatements } else { CF:ControlStatements} R:ControlStatements)
        => @processAssert(CT) ~> @processAssert(CF) ~> @processAssert(R)

    rule <k> @processAssert(@assert [I] E; R:ActionStatements => R) ... </k>
         <assertions>
            (.Bag => <assertion>
                <assertId>      I     </assertId>
                <result>        E    </result>
                ...
            </assertion>)
            ...
         </assertions>

    rule <k> @processAssert(@assert [I] E; R:ControlStatements => R) ... </k>
         <assertions>
           (.Bag => <assertion>
               <assertId>    I  </assertId>
               <result>      E    </result>
               ...
           </assertion>)
           ...
         </assertions>



    // --------------------------- partial evaluation ---------------------------

    syntax PartEvalBoolExpr ::=  "$partEval" "(" BoolExpr ")"
    syntax BoolExpr ::= PartEvalBoolExpr
    syntax KResult ::= PartEvalBoolExpr

    // context @assert [_] HOLE:PartEvalBoolExpr;
    // Didn't work
    rule <k> (.K => B) ~> @assert [_] B:BoolExpr; ... </k>
         <evalMode> NO_EVAL => PARTIAL_EVAL </evalMode>


//    rule <k> B:Bool => $partEval(B)  ... </k>
//         <evalMode> PARTIAL_EVAL </evalMode> kompile error
    syntax KItem ::= "@bool2partEval" "(" Bool ")"
    rule <k> B:Bool => @bool2partEval(B)  ... </k>
         <evalMode> PARTIAL_EVAL </evalMode>
    rule @bool2partEval(B) => $partEval(B)

    rule <k> #isReached => $partEval(true) ... </k>
         <evalMode> PARTIAL_EVAL </evalMode>
    rule <k> #isForwarded => $partEval(#isForwarded) ... </k>
         <evalMode> PARTIAL_EVAL </evalMode>
    rule <k> #isDeparsed (H) => $partEval(#isDeparsed(H)) ... </k>
         <evalMode> PARTIAL_EVAL </evalMode>
    rule <k> #isUndef (H) => $partEval(#isUndef(H)) ... </k>
         <evalMode> PARTIAL_EVAL </evalMode>
    syntax Exp ::= "#isConstantExpr" "(" FieldRef ")"
    rule <k> #isConstant(H) => $partEval(#isConstantExpr(H) == H) ... </k>
         <evalMode> PARTIAL_EVAL </evalMode>

    rule <k> not B:PartEvalBoolExpr => $partEval(not B) ...</k>
         <evalMode> PARTIAL_EVAL </evalMode>
    rule <k> B1:PartEvalBoolExpr and B2 => $partEval(B1 and B2) ...</k>
         <evalMode> PARTIAL_EVAL </evalMode>
    rule <k> B1 and B2:PartEvalBoolExpr => $partEval(B1 and B2) ...</k>
         <evalMode> PARTIAL_EVAL </evalMode>
    rule <k> B1:PartEvalBoolExpr or B2 => $partEval(B1 or B2) ...</k>
         <evalMode> PARTIAL_EVAL </evalMode>

    rule <k> (E:PartEvalBoolExpr ~> @assert [I] _ ;) => .K ... </k>
         <assertion>
            <assertId>  I       </assertId>
            <result>    _ => E  </result>
            ...
         </assertion>
         <evalMode> PARTIAL_EVAL => NO_EVAL </evalMode>


    // --------------------------- final evaluation ---------------------------

    rule <k> (.K => @evalNextAssert) ~> @drop ... </k>
         <evalMode> NO_EVAL => FINAL_EVAL </evalMode>
         <forwarded> _ => false </forwarded>
         [priority(49)]

    rule <k> (.K => @evalNextAssert) ~> @txenPacket ... </k>
         <evalMode> NO_EVAL => FINAL_EVAL </evalMode>
         <forwarded> _ => true </forwarded>
         [priority(49)]

    syntax KItem ::= "@evalNextAssert" | "@evalAssert" "(" Id /* assert id */")"
    rule <k> @nextPacket ... </k>
         <evalMode> FINAL_EVAL => NO_EVAL </evalMode>
         [priority(49)]

    rule <k> (.K => B ~> @evalAssert(I)) ~> @evalNextAssert ... </k>
         <assertion>
            <assertId> I </assertId>
            <result> B </result>
            ...
         </assertion>
         when notBool isBool(B)
    rule <k> @evalNextAssert => . ... </k> [owise]

    rule <k> B:Bool ~> @evalAssert(I) => . ... </k>
          <assertion>
             <assertId> I </assertId>
             <result> _ => B </result>
             ...
          </assertion>

    rule <k> $partEval(B) => B ... </k>
         <evalMode> FINAL_EVAL </evalMode>
    rule <k> not $partEval(B) => not B ... </k>
         <evalMode> FINAL_EVAL </evalMode>
    rule <k> $partEval(B1) and B2 => B1 and B2 ... </k>
         <evalMode> FINAL_EVAL </evalMode>
    rule <k> B1 and $partEval(B2) => B1 and B2 ... </k>
         <evalMode> FINAL_EVAL </evalMode>
    rule <k> $partEval(B1) or B2 => B1 or B2 ... </k>
         <evalMode> FINAL_EVAL </evalMode>
    rule <k> B1 or $partEval(B2) => B1 or B2 ... </k>
         <evalMode> FINAL_EVAL </evalMode>
    rule <k> $partEval(#isConstantExpr(H) == V) => H == V ... </k>
         <evalMode> FINAL_EVAL </evalMode>
    rule <k> (.K => H) ~> #isUndef(H) ...</k>
         <evalMode> FINAL_EVAL </evalMode>
    rule <k> @undef ~> #isUndef(_) => true ...</k>
         <evalMode> FINAL_EVAL </evalMode>
    rule <k> @val(_,_,_) ~> #isUndef(_) => false ...</k>
         <evalMode> FINAL_EVAL </evalMode>

//    rule <k> @init ... </k>
//         <in> .List =>
//            ListItem($packet(
//                "00000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000001000000000000100010100000000000000000100010010101101000010110000000000000000010000000001000101110010011100100000101000000000000000000000000100001010000000000000000000000000"
//                , 2))
//         </in>
//    [priority(49)]

endmodule




//module P4ASSERT-CLI-SYMBOLIC-MAINMODULE
//imports P4ASSERT-CLI-SYMBOLIC-SEMANTICS
//    configuration <p4/>
//                  <p4assert/>
//                  <CLI/>
//                  <p4assert-cli-semantics-load>
//                      @loadP4Program($PGM:P4Program) ~> @loadCLIProgram($CLI:CLIPgm)
//                  </p4assert-cli-semantics-load>
//
//
//    syntax KItem ::= "@loadP4Program" "(" P4Program ")"
//    syntax KItem ::= "@loadCLIProgram" "(" CLIPgm ")"
//    rule <p4assert-cli-semantics-load>
//            (@loadP4Program(Program) ~> @loadCLIProgram(Pgm)) => .K
//         </p4assert-cli-semantics-load>
//         <k> _ => @runP4Program(Program) </k>
//         <cli-k> _ => Pgm </cli-k>
//endmodule




 //    // --------------------------- execution ---------------------------
    //
    //    rule <k> @assert [I] E ; R:ControlStatements => R ... </k>
    //         <assertion>
    //            <assertId>      I  </assertId>
    //            <result>    E => #partialEvalAssertExp(E)  </result>
    //            <assertReached> false => true </assertReached>
    //         </assertion>
    //
    //    syntax BoolExpr ::= #partialEvalAssertExp(BoolExpr) [function]
    //    rule #partialEvalAssertExp(not B)       => not #partialEvalAssertExp(B)
    //    rule #partialEvalAssertExp(B1 and B2)   => #partialEvalAssertExp(B1) and #partialEvalAssertExp(B2)
    //    rule #partialEvalAssertExp(B1 or B2)    => #partialEvalAssertExp(B1) or #partialEvalAssertExp(B2)
    //    rule #partialEvalAssertExp(#isReached)  => true
    //    rule #partialEvalAssertExp(B)           => B [owise]
    //    rule #partialEvalAssertExp(#isValid(H:HeaderRef . _:FieldName)) =>  #partialEvalAssertExp(#isValid(H))
    //    rule [[ #partialEvalAssertExp(#isValid(H:HeaderRef)) => V ]]
    //          <instance> <name> H </name> <valid> V:Bool </valid>  ...  </instance>
