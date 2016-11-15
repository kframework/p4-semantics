require "header-syntax.k"

module PARSER

endmodule

module PARSER-SYNTAX
imports HEADER-SYNTAX //only for header reference
imports VALUE-SYNTAX
    syntax ValueSetName ::= Id
    syntax InstanceName ::= Id
    syntax ParserStateName ::= Id
    syntax ControlFunctionName ::= Id
    syntax ParserExceptionName ::= Id


// 4.3 ValueSets
   // This is a named set of values with a run time API to add and remove values from the set.
   syntax ValueSetDeclaration ::= "parser_value_set" ValueSetName ";"

// 4.4 ParserFunction
    syntax ParserFunctionDeclaration ::= "parser" ParserStateName "{" ParserFunctionBody "}"

    syntax ParserFunctionBody ::=
                  ExtractOrSetStatements
                  ReturnStatement

    syntax ExtractOrSetStatements ::= List{ExtractOrSetStatement, ""}
    syntax ExtractOrSetStatement ::= ExtractStatement | SetStatement

    syntax ExtractStatement ::= "extract" "(" HeaderExtractRef ")" ";"


    syntax HeaderExtractRef ::=
                      InstanceName
                    | InstanceName "[" HeaderExtractIndex "]"

    syntax HeaderExtractIndex ::=
                  ConstValue
                | "next"

    syntax SetStatement ::= "set_metadata" "(" FieldRef "," MetadataExpr ")" ";"
    syntax MetadataExpr ::= FieldValue | FieldOrDataRef

    syntax ReturnStatement ::=
                  ReturnValueType
                | "return" "select" "(" SelectExp ")" "{" CaseEntries "}"



    syntax ReturnValueType ::=
                  "return" ParserStateName ";"
                | "return" ControlFunctionName ";"
                | "parse_error" ParserExceptionName ";"

    syntax CaseEntries ::= NeList{CaseEntry,""}     [klabel('CaseEntries)]
    syntax CaseEntry ::= ValueList ":" CaseReturnValueType ";"

    syntax ValueList ::= ValueOrMaskeds | "default"

    syntax CaseReturnValueType ::=
              ParserStateName
            | ControlFunctionName
            | "parse_error" ParserExceptionName

    syntax ValueOrMaskeds ::= NeList{ValueOrMasked,","} [klabel('ValueOrMaskeds)]
    syntax ValueOrMasked ::=
                  FieldValue
                | FieldValue "mask" FieldValue
                | ValueSetName
               // | "(" ValueOrMaskeds ")"

    syntax SelectExp ::= FieldOrDataRefs

    syntax FieldOrDataRefs ::= NeList{FieldOrDataRef,","}   [klabel('FieldOrDataRefs)]
    syntax FieldOrDataRef ::=
                  FieldRef
                | "latest" "." FieldName
                | "current" "(" ConstValue "," ConstValue ")"


endmodule

module PARSER-EXCEPTION-SYNTAX
imports PARSER-SYNTAX
    syntax  ParserExceptionName ::= Id

// 4.6 ParserExceptions
    syntax ParserExceptionDeclaration ::=
                    "parser_exception" ParserExceptionName "{"
                        SetStatements
                        ReturnOrDrop ";"
                    "}"
    syntax SetStatements ::= List{SetStatement,""}    [klabel('SetStatements)]

    syntax ReturnOrDrop ::= ReturnToControl | "parser_drop"
    syntax ReturnToControl ::= "return" ControlFunctionName
endmodule