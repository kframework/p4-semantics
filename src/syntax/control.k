module CONTROL-SYNTAX
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
    //todo
    syntax ActionCases ::= ActionCase | ActionCases ActionCases
    //todo
    syntax HitMissCases ::= HitMissCase | HitMissCases HitMissCases

    syntax ActionCase ::= ActionOrDefault ControlBlock
    syntax ActionOrDefault ::= ActionName | "default"

    syntax HitMissCase ::= HitOrMiss ControlBlock
    syntax HitOrMiss ::= "hit" | "miss"

    syntax IfElseStatement ::= "if" "(" BoolExpr ")" ControlBlock OptionalElseBlock
    syntax OptionalElseBlock ::= None | ElseBlock

    syntax ElseBlock ::= "else" ControlBlock | "else" IfElseStatement

    syntax BoolExpr ::=
                      "valid" "(" ObjectRef ")"
                    | BoolExpr BoolOp BoolExpr
                    | "not" BoolExpr
                    | "(" BoolExpr ")"
                    | Exp ReOp Exp
                    | BoolValue
    syntax  Exp ::= Exp BinOp Exp | UnOp Exp | FieldRef | Value | "(" Exp ")"

    syntax BinOp ::= "+" | "*" | "-" | "<<" | ">>" | "&" | "|" | "^"
    syntax UnOp ::= "~"  | "-"
    syntax BoolOp ::= "or" | "and"
    syntax Relop ::= ">" | ">=" | "==" | "<=" | "<" | "!="
endmodule
