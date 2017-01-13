require "table-syntax.k"

module CONTROL

endmodule

module CONTROL-SYNTAX
imports TABLE-SYNTAX //for VALUE-SYNTAX and HeaderRef and TableName
imports PARSER-SYNTAX //for ControlFunctionName

// 12 Packet Processing and Control Flow
    syntax ControlFunctionDeclaration ::= "control" ControlFunctionName ControlBlock
    syntax ControlBlock ::= "{" ControlStatements "}"
    syntax ControlStatements ::= List{ControlStatement,""} [klabel('ControlStatements)]
    syntax ControlStatement ::=
                  ApplyTableCall            //[klabel(ContStmApp)]
                | ApplyAndSelectBlock       //[klabel('ContStmAppSel)]
                | IfElseStatement           //[klabel('ContStmIf)]
                | ControlFunctionName "(" ")" ";" //[klabel('ContStmFn)]
                //| "return" ";"


    syntax ApplyTableCall ::= "apply" "(" TableName ")" ";"

    syntax ApplyAndSelectBlock ::= "apply" "(" TableName ")" "{"  CaseList "}"
    syntax CaseList ::= ActionCases | HitMissCases

    syntax ActionCases ::= NeList{ActionCase,""}         [klabel('ActionCases)]
    syntax HitMissCases ::= NeList{HitMissCase,""}       [klabel('HitMissCases)]

    syntax ActionCase ::= ActionOrDefault ControlBlock
    syntax ActionOrDefault ::=
              ActionName
            | "default" [klabel('Default)]

    syntax HitMissCase ::= HitOrMiss ControlBlock
    syntax HitOrMiss ::= "hit" | "miss"

    syntax IfElseStatement ::=
          "if" "(" BoolExpr ")" ControlBlock //OptionalElseBlock
        | "if" "(" BoolExpr ")" ControlBlock ElseBlock
    //syntax OptionalElseBlock ::= None | ElseBlock

    syntax ElseBlock ::= "else" ControlBlock | "else" IfElseStatement

    syntax BoolExpr ::=
                      "valid" "(" HeaderRef ")"         [klabel('BExpValid)]
                    | BoolExpr BoolOp BoolExpr          [klabel('BExpBinBoolOp)]//TODO: assoc according to C
                    | "not" BoolExpr                    [klabel('BExpBinNot)]
                    | "(" BoolExpr ")"                  [braket, klabel('BExpBinNot)]
                    | Exp RelOp Exp                     [klabel('BExpBinRelOp)]//TODO: assoc according to C
                    | BoolValue                         [klabel('BExpVal)]
    //syntax  Exp ::= Exp BinOp Exp | UnOp Exp | FieldRef | Value | "(" Exp ")"
    syntax  Exp ::=
          Exp BinOp Exp [klabel('ExpBinOp)]
        | UnOp Exp      [klabel('BExpUnOp)]
        | FieldRef      [klabel('BExpFieldRef)]
        | ConstValue    [klabel('BExpConst)]
        | "(" Exp ")"   [klabel('BExpUnOp)]
    //TODO ISSUE: what is Value ?

    //TODO: priorities according to C
    syntax BinOp ::= "+" | "*" | "-" | "<<" | ">>" | "&" | "|" | "^"
    syntax UnOp ::= "~"  | "-"
    syntax BoolOp ::= "or" | "and"
    syntax RelOp ::= ">" | ">=" | "==" | "<=" | "<" | "!="
endmodule
