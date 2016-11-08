module PARSER-SYNTAX
// 4.3 ValueSets
   syntax ValueSetDeclaration ::= "parser_value_set" ValueSetName ";"

// 4.4 ParserFunction
syntax ParserFunctionDeclaration ::= "parser" ParserStateName "{" ParserFunctionBody "}"


    syntax ParserFunctionBody ::= ExtractOrSetStatements


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
    //todo
    syntax CaseEntries ::= CaseEntrie | CaseEntries CaseEntries

    syntax ReturnValueType ::=
                  "return" ParserStateName ";"
                | "return" ControlFunctionName ";"
                | "parse_error" ParserExceptionName ";"


    syntax CaseEntry ::= ValueList ":" CaseReturnValueType ";"
    syntax ValueList ::= ValueOrMaskeds | "default"
    //todo
    syntax ValueOrMaskeds ::= ValueOrMasked | ValueOrMaskeds "," ValueOrMaskeds

    syntax CaseReturnValueType ::=
              ParserStateName
            | ControlFunctionName
            | "parse_error" ParserExceptionName

    syntax ValueOrMasked ::=
                  FieldValue
                | FieldValue "mask" FieldValue
                | ValueSetName
               // | "(" ValueOrMaskeds ")"

    syntax SelectExp ::= FieldOrDataRefs
    //todo
    syntax FieldOrDataRefs ::= FieldOrDataRef | FieldOrDataRefs "," FieldOrDataRefs


    syntax FieldOrDataRef ::=
                  FieldRef
                | "latest" "." FieldName
                | "current" "(" ConstValue "," ConstValue ")"










// 4.6 ParserExceptions
      syntax ParserExceptionDeclaration ::=
                    "parser_exception" ParserExceptionName "{"
                        SetStatements
                        ReturnOrDrop ";"
                    "}"
        syntax SetStatements ::= List{SetStatement,""}

        syntax ReturnOrDrop ::= ReturnToControl | "parser_drop"
        syntax ReturnToControl ::= "return" ControlFunctionName

endmodule