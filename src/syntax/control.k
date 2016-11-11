require "table.k"

module CONTROL

endmodule

module CONTROL-SYNTAX
imports TABLE-SYNTAX //for VALUE-SYNTAX and HeaderRef and TableName
    syntax ControlFnName ::= Id
// 12 Packet Processing and Control Flow
    syntax ControlFunctionDeclaration ::= "control" ControlFnName ControlBlock
    syntax ControlBlock ::= "{" ControlStatements "}"
    syntax ControlStatements ::= List{ControlStatement,""}
    syntax ControlStatement ::=
                  ApplyTableCall
                | ApplyAndSelectBlock
                | IfElseStatement
                | ControlFnName "(" ")" ";"
                //| "return" ";"


    syntax ApplyTableCall ::= "apply" "(" TableName ")" ";"

    syntax ApplyAndSelectBlock ::= "apply" "(" TableName ")" "{"  CaseList "}"
    syntax CaseList ::= ActionCases | HitMissCases

    syntax ActionCases ::= NeList{ActionCase,""}
    syntax HitMissCases ::= NeList{HitMissCase,""}

    syntax ActionCase ::= ActionOrDefault ControlBlock
    syntax ActionOrDefault ::= ActionName | "default"

    syntax HitMissCase ::= HitOrMiss ControlBlock
    syntax HitOrMiss ::= "hit" | "miss"

    syntax IfElseStatement ::= "if" "(" BoolExpr ")" ControlBlock OptionalElseBlock
    syntax OptionalElseBlock ::= None | ElseBlock

    syntax ElseBlock ::= "else" ControlBlock | "else" IfElseStatement

    syntax BoolExpr ::=
                      "valid" "(" HeaderRef ")"
                    | BoolExpr BoolOp BoolExpr //TODO: assoc according to C
                    | "not" BoolExpr
                    | "(" BoolExpr ")"
                    | Exp RelOp Exp  //TODO: assoc according to C
                    | BoolValue
    //syntax  Exp ::= Exp BinOp Exp | UnOp Exp | FieldRef | Value | "(" Exp ")"
    syntax  Exp ::= Exp BinOp Exp | UnOp Exp | FieldRef | ConstValue | "(" Exp ")"
    //TODO ISSUE: what is Value ?

    //TODO: priorities according to C
    syntax BinOp ::= "+" | "*" | "-" | "<<" | ">>" | "&" | "|" | "^"
    syntax UnOp ::= "~"  | "-"
    syntax BoolOp ::= "or" | "and"
    syntax RelOp ::= ">" | ">=" | "==" | "<=" | "<" | "!="
endmodule
