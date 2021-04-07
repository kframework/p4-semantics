// based on P4 Language Spec Version 1.1.0 Jan 2016

module P4-SYNTAX

    syntax P4Program ::= P4Declerations

    //todo: nonempty list?
    syntax P4Declarations ::= P4Declaration | P4Declarations P4Declerations



    syntax P4Decleration ::=
                  HeaderTypeDeclaration
                | HeaderInstanceDeclaration
                | FieldListDeclaration
                | FieldListCalculationDeclaration
                | CalculatedFieldDeclaration
                | ValueSetDeclaration
                | ParserFunctionDeclaration
                | ParserExceptionDeclaration
                | CounterDeclaration
                | MeterDeclaration
                | RegisterDeclaration
                | PrimitiveActionDeclaration
                | ActionFunctionDeclaration
                | ActionProfileDeclaration
                | ActionSelectorDeclaration
                | TableDeclaration
                | ExternTypeDeclaration
                | ExternInstanceDeclaration
                | ControlFunctionDeclaration

    syntax ConstValue ::=
                  BoolValue
                | Sign OptionalWidthSpec UnsignedValue

    syntax OptionalWidthSpec ::= None | WidthSpec

    syntax Sign ::= "+" | "-"

// unsigned_value ::= binary_value | decimal_value | hexadecimal_value
    syntax UnsignedValue ::= BinaryValue | DecimalValue | HexadecimalValue

    syntax BoolValue ::= "true" | "false"


  // syntax binary_value ::= binary_base binary_digit+
  // syntax decimal_value ::= decimal_digit+
  // syntax hexadecimal_value ::= hexadecimal_base hexadecimal_digit+

  // syntax binary_base ::= 0b | 0B
  // syntax hexadecimal_base ::= 0x | 0X

  // syntax binary_digit ::= _ | 0 | 1
  // syntax decimal_digit ::= binary_digit | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9
  // syntax hexadecimal_digit ::= decimal_digit | a | A | b | B | c | C | d | D | e | E | f | F

    syntax _BinaryValue ::= Token{("0b" | "0B")[0-9]+} [notInRules]
    syntax _DecimalValue ::= Token{[0-9]+} [notInRules]
    syntax _HexadecimalValue ::= Token{("0x" | "0X")[0-9]+} [notInRules]

    syntax BinaryValue ::= _BinaryValue
    syntax DecimalValue ::= _DecimalValue
    syntax HexadecimalValue ::= _HexadecimalValue

// width_spec ::= decimal_digit+ w | decimal_digit+ s
    syntax WidthSpec ::= _DecimalValue WS
    syntax WS ::= "w" | "s"

    syntax  FieldValue ::= ConstValue

    syntax TypeSpec ::=
              "header" OptionalHeaderTypeName
            | "metadata" OptionalHeaderTypeName
            | "field_list"
            | "field_list_calculation"
            | "parser"
            | "parser_exception"
            | "parser_value_set"
            | "counter"
            | "meter"
            | "register"
            | "action"
            | "action_profile"
            | "table"
            | "control"
            | "extern" OptionalExternTypeName
            | DataType

    syntax OptionalHeaderTypeName ::= None | HeaderTypeName
    syntax OptionalExternTypeName ::= None | ExternTypeName

//data_type ::= bit | bit < decimal_digit+ > | varbit < decimal_digit+ > | int < decimal_digit+ >
    syntax DataType ::=
              "bit"
            | "bit" "<" _DecimalValue ">"
            | "varbit" "<" _DecimalValue ">"
            | "int" "<" _DecimalValue ">"

    syntax  ObjectRef ::= "instance_name" | HeaderRef | FieldRef

    syntax GeneralExpr ::= BoolExpr | ArithExpr | ConstExpr | ObjectRef

    syntax BoolExpr ::=
                      "valid" "(" ObjectRef ")"
                    | BoolExpr BoolOp BoolExpr
                    | "not" BoolExpr
                    | "(" BoolExpr ")"
                    | ArithExpr RelOp ArithExpr
                    | BoolValue

    syntax ArithExpr ::=
                     ObjectRef
                   | ConstValue
                   | MinMax "(" ArithExpr "," ArithExpr ")"
                   | "(" arith_expr ")"
                   | ArithExpr BinOp ArithExpr
                   | UnOp ArithExpr
                   | "(" DataType ")" ArithExpr

    syntax MinMax ::= "min" | "max"

    syntax ConstExpr ::=
          ConstValue
        | MinMax "(" ConstExpr "," ConstExpr ")"
        | "(" ConstExpr ")"
        | ConstExpr BinOp ConstExpr
        | UnOp ConstExpr


    syntax BinOp ::= "+" | "*" | "-" | "<<" | ">>" | "&" | "|" | "^"
    syntax UnOp ::= "~"  | "-"
    syntax BoolOp ::= "or" | "and"
    syntax Relop ::= ">" | ">=" | "==" | "<=" | "<" | "!="

    syntax P4Pragma ::= "@pragma" PragmaName PragmaText

    syntax HeaderTypeDeclaration ::= "header_type" HeaderTypeName "{" HeaderDecBody "}"

    syntax HeaderDecBody ::= "fields" "{" FieldDecs "}" OptionalLengthDec

    syntax OptionalLengthDec ::= None | "length" ":" LengthExp ";"

    syntax FieldDec ::= DataType FieldName ";"
    syntax LengthBinOp ::= "+" | "-" | "*" | "<<" | ">>"
    syntax LengthExp ::=
                  ConstExpr
                | FieldName
                | LengthExp LengthBinOp LengthExp
                | "(" LengthExp ")"

    syntax HeaderInstanceDeclaration ::= HeaderInstance | MetadataInstance
    syntax HeaderInstance ::= ScalarInstance | ArrayInstance
    syntax ScalarInstance ::= "header" HeaderTypeName InstanceName ";"
    syntax ArrayInstance ::= "header" HeaderTypeName InstanceName "[" ConstExpr "]" ";"

    syntax MetadataInstance ::= "metadata" HeaderTypeName InstanceName OptionalMetadataInitializer  ";"

    syntax OptionalMetadataInitializer ::= None | MetadataInitializer


// metadata_initializer ::= { [ field_name : field_value ; ] + }
    syntax MetadataInitializer ::= "{" FieldValueAssignments "}"
    //todo: nonempty list ?
    syntax FieldValueAssignments ::= FieldValueAssignment | FieldValueAssignments FieldValueAssignment
    syntax FieldValueAssignment ::= FieldName ":" FieldValue ":"

    syntax HeaderRef ::=
              HeaderInstanceName
            | HeaderInstanceName "[" HeaderRefIndex "]"

    syntax HeaderRefIndex ::= ConstExpr | "last" | "next"

    syntax FieldRef ::= HeaderRef "." FieldName
    syntax FieldListDeclaration ::=
                "field_list" FieldListName "{"
                    FieldListEntries
                "}"
// [ field_list_entry ; ] *
    syntax FieldListEntries ::= List{FieldListEntry,";"}

//  [ field_list_name ; ] +
    syntax FieldListEntry ::= ObjectRef | FieldValue
    syntax FieldListCalculationDeclaration ::=
            "field_list_calculation" FieldListCalculationName "{"
                "input" "{"
                    FieldListNames
                "}"
                "algorithm" ":" StreamFunctionAlgorithmName ";"
                "output_width" ":" ConstExpr ";"
            "}"
    //todo: non-empty list
    syntax FieldListNames ::= FieldListName | FieldListNames FieldListName
    syntax CalculatedFieldDeclaration ::= "calculated_field" FieldRef "{" UpdateVerifySpecs "}"
    //todo: non-empty list
    syntax UpdateVerifySpecs ::= UpdateVerifySpec | UpdateVerifySpecs UpdateVerifySpec

    syntax UpdateVerifySpec ::= UpdateOrVerify FieldListCalculationName OptionalIfCond ";"
    syntax OptionalIfCond ::= None | IfCond

    syntax UpdateOrVerify ::= "update" | "verify"
    syntax IfCond ::= "if" "(" CalcBoolCond ")"
    syntax CalcBoolCond ::=
                  "valid" "(" HeaderOrFieldRef ")"
                | FieldRef "==" FieldRef
    syntax HeaderOrFieldRef ::= HeaderRef | FieldRef
    syntax ValueSetDeclaration ::= "parser_value_set" ValueSetName ";"
    syntax ParserFunctionDeclaration ::= "parser" ParserStateName "{" ParserFunctionBody "}"

    syntax ParserFunctionBody ::= ParserBodyCalls return_statement

    syntax ParserBodyCalls ::= List{ParserBodyCall, ""}

    syntax ParserBodyCall ::=
                  ExtractStatement
                | SetStatement
                | ExternMethodCall ";"

    syntax ExtractStatement ::= "extract" "(" HeaderExtractRef ")" ";"

    syntax HeaderExtractRef ::=
                      HeaderInstanceName
                    | HeaderInstanceName "[" HeaderExtractIndex "]"

    syntax HeaderExtractIndex ::= ConstExpr | "next"

    syntax SetStatement ::= "set_metadata" "(" FieldRef "," GeneralExpr ")" ";"

    syntax ReturnStatement ::=
                  ReturnValueType
                | "return" "select" "(" SelectExp ")" "{" CaseEntries "}"
    //todo
    syntax CaseEntries ::= CaseEntrie | CaseEntries CaseEntrie

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
                | "(" ValueOrMaskeds ")"

    syntax SelectExp ::= FieldOrDataRefs
    //todo
    syntax FieldOrDataRefs ::= FieldOrDataRef | FieldOrDataRefs "," FieldOrDataRef


    syntax FieldOrDataRef ::=
                  FieldRef
                | "latest" "." FieldName
                | "current" "(" ConstExpr "," ConstExpr ")"
    syntax ParserExceptionDeclaration ::=
                "parser_exception" ParserExceptionName "{"
                    SetStatements
                    ReturnOrDrop ";"
                "}"
    syntax SetStatements ::= List{SetStatement,""}

    syntax ReturnOrDrop ::= ReturnToControl | "parser_drop"
    syntax ReturnToControl ::= "return" ControlFunctionName

    syntax CounterDeclaration ::=
                    "counter" CounterName "{"
                        "type" ":" CounterType ";"
                        OptionalDirectOrStatic
                        OptionalInstantCount
                        OptionalMinWidth
                        OptionalSaturating
                    "}"
    syntax OptionalDirectOrStatic ::= None |  OptionalDirectOrStatic ";"
    syntax OptionalInstantCount ::= None | "instance_count" ":" ConstExpr ";"
    syntax OptionalMinWidth ::= None | "min_width" ":" ConstExpr ";"
    syntax OptionalSaturating ::= None | "saturating" ";"

    syntax CounterType ::= "bytes" | "packets" | "bytes_and_packets"
    syntax DirectOrStatic ::= DirectAttribute | StaticAttribute
    syntax DirectAttribute ::= "direct" ":" TableName
    syntax StaticAttribute ::= "static" ":" TableName

    syntax MeterDeclaration ::=
            "meter" MeterName "{"
                "type" ":" MeterType ";"
                OptionalResult
                OptionalDirectOrStatic
                OptionalInstantCount
            "}"

    syntax OptionalResult ::= None | "result" ":" FieldRef ";"
    syntax OptionalInstantCount ::= None | "instance_count" ":" ConstExpr ";"

    syntax MeterType ::= "bytes" | "packets"

    syntax RegisterDeclaration ::=
            "register" RegisterName "{"
                WidthOrLayout ";"
                OptionalDirectOrStatic
                OptionalInstantCount
                OptionalAttributeList
            "}"

    syntax OptionalAttributeList ::= None | AttributeList ";"

    syntax WidthOrLayout ::= WidthDeclaration | LayoutDeclaration
    syntax WidthDeclaration ::= "width" ":" ConstExpr
    syntax LayoutDeclaration ::= "layout" ":" HeaderTypeName

    syntax AttributeList ::= "attributes" ":" AttrEntry
    syntax AttrEntry ::= "signed" | AttrEntry "," AttrEntry
    syntax RegisterRef ::= RegisterName "[" ConstExpr "]" OptionalFieldRef
    syntax OptionalFieldRef ::= None | "." FieldName
    syntax CompoundActionFunctionDeclaration ::=
                  "action" ActionName "(" ActionParamList ")" "{" ActionStatements "}"
                | "action" ActionName "(" ActionParamList ")" ";"
    syntax ActionParamList ::= List{ActionParam,","}
    syntax ActionStatements ::= List{ActionStatements,""}

    syntax ActionParam ::= ParamQualifiers DataType ParamName
    syntax ParamQualifiers ::= List{ParamQualifier," "}

    syntax ParamQualifier ::= "in" | "inout"

    syntax ActionStatement ::=
                  ActionName "(" ArgList ")" ";"
                | ExternMethodCall ";"

    syntax ArgList ::= List{GeneralExpr, ","}

    syntax ActionProfileDeclaration ::=
            "action_profile" ActionProfileName "{"
                ActionSpecification
                OptionalSize
                OptionalDynamicActionSelection
            "}"

    syntax OptionalSize ::= None | "size" ":" ConstExpr ";"
    syntax OptionalDynamicActionSelection ::= "dynamic_action_selection" ":" SelectorName ";"

    syntax ActionSpecification ::= "actions" "{" ActionNames "}"
    syntax ActionaNames ::= ActionName ";" | ActionaNames ActionaNames


    syntax ActionSelectorDeclaration ::=
            "action_selector" SelectorName "{"
                "selection_key" ":" FieldListCalculationName ";"
            "}"

    syntax TableDeclaration ::=
            "table" TableName "{"
                OptionalReads
                TableActions
                OptionalSize
                OptionalSupportTimeout
            "}"

    syntax OptionalReads :: = None | "reads" "{" FieldMatchs "}"
    //todo
    syntax FieldMatchs ::= FieldMatch | FieldMatchs FieldMatchs

    syntax OptionalSize ::= None |  Size ":" ConstExpr ";"
    syntax Size ::= "min_size" | "max_size" | "size"

    syntax OptionalSupportTimeout ::= "support_timeout" ":" BoolValue ";"

    syntax FieldMatch ::= FieldOrMaskedRef ":" FieldMatchType ";"
    syntax FieldOrMaskedRef ::= HeaderRef | FieldRef | FieldRef "mask" ConstExpr

    syntax FieldMatchType ::= "exact" | "ternary" | "lpm" | "index" | "range" | "valid"

    syntax TableActions ::= ActionSpecification | ActionProfileSpecification

    syntax ActionProfileSpecification ::= "action_profile" ":" ActionProfileName ";"
    syntax ControlFunctionDeclaration ::= "control" ControlFnName ControlBlock
    syntax ControlBlock ::= "{" ControlStatements "}"
    syntax ControlStatements ::= List{ControlStatement,""}
    syntax ControlStatement ::=
                  ApplyCall
                | ApplyAndSelectBlock
                | ExternMethodCall ";"
                | IfElseStatement
                | ControlFnName "(" ")" ";"
                | "return" ";"

    syntax ApplyCall ::= "apply" "(" TableName ")" ";"
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

    syntax ExternTypeDeclaration ::=
            "extern_type" TypeName "{"
                MemberDeclarations
            "}"
    syntax MemberDeclarations ::= List{MemberDeclaration,""}


    syntax MemberDeclaration ::= AttributeDeclaration | MethodDeclaration

    syntax MethodDeclaration ::= "method" MethodName "(" MethodParamList ")" ";"

    syntax MethodParamList ::= List{MethodParam,","}

    syntax MethodParam ::= ParamQualifiers TypeSpec ParamName

    syntax AttributeDeclaration ::=
            "attribute" AttributeName "{"
                "type" ":" AttributeType ";"
                OptionalOptional
            "}"

    syntax OptionalOptional ::= None | "optional" ";"

    //identifier_list ::= variable_name ; ???

    syntax AttributeType ::= TypeSpec

    syntax ExternInstanceDeclaration ::=
                "extern" TypeName InstanceName ";"
              | "extern" TypeName InstanceName "{" ExternAttributeBindings "}"

    //todo
    syntax ExternAttributeBindings ::= ExternAttributeBinding | ExternAttributeBindings ExternAttributeBindings

    //extern_attribute_binding ::= attribute_name : object_ref | general_expr;
    syntax ExternAttributeBindings ::= AttributeName ":" ObjectRefOrGeneralExpr
    syntax ObjectRefOrGeneralExpr ::= ObjectRef | GeneralExpr

    syntax ExternMethodCall ::= ObjectRef "." MethodName "(" ArgList ")"

endmodule