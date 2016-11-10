module HEADER

endmodule

module HEADER-SYNTAX
    syntax HeaderTypeName ::= Id
    syntax InstanceName ::= Id
    syntax FieldName ::= Id
    syntax HeaderInstanceName ::= Id
    syntax FieldListName ::= Id
    syntax None ::= ""

    //todo: temp - fix this
    syntax ConstValue ::= Int
    syntax FieldValue ::= ConstValue

// 2.1 HeaderTypeDeclarations
    syntax HeaderTypeDeclaration ::= "header_type" HeaderTypeName "{" HeaderDecBody "}"

    syntax HeaderDecBody ::= "fields" "{" FieldDecs "}" OptionalLengthDec OptionalMaxLengthDec


    syntax OptionalLengthDec ::= None | "length" ":" LengthExp ";"
    syntax OptionalMaxLengthDec ::= None | "max_length" ":" ConstValue ";"

    syntax FieldDecs ::= NeList{FieldDec,""}
    syntax FieldDec ::= FieldName ":" BitWidth OptionalFieldMod ";"
    syntax OptionalFieldMod ::= None | FieldMod
    syntax FieldMod ::= "signed" | "saturating" | FieldMod "," FieldMod
    syntax LengthBinOp ::= "+" | "-" | "*" | "<<" | ">>"
    syntax LengthExp ::=
                  ConstValue
                | FieldName
                | LengthExp LengthBinOp LengthExp
                | "(" LengthExp ")"
    syntax BitWidth ::= ConstValue | "*"


// 2.2 HeaderandMetadataInstances
    syntax InstanceDeclaration ::= HeaderInstance | MetadataInstance
    syntax HeaderInstance ::= ScalarInstance | ArrayInstance
    syntax ScalarInstance ::= "header" HeaderTypeName InstanceName ";"
    syntax ArrayInstance ::= "header" HeaderTypeName InstanceName "[" ConstValue "]" ";"

    syntax MetadataInstance ::=
                      "metadata" HeaderTypeName ";"
                    |  "metadata" HeaderTypeName  InstanceName OptionalMetadataInitializer
    //?????

    syntax OptionalMetadataInitializer ::= None | MetadataInitializer


    syntax MetadataInitializer ::= "{" FieldValueAssignments "}"

    syntax FieldValueAssignments ::= NeList{FieldValueAssignment,""}
    syntax FieldValueAssignment ::= FieldName ":" FieldValue ";"


// 2.3 HeaderandFieldReferences
    syntax HeaderRef ::=
              HeaderInstanceName
            | HeaderInstanceName "[" Index "]"

    syntax Index ::= ConstValue | "last"

    syntax FieldRef ::= HeaderRef "." FieldName




// 2.4 FieldLists
    syntax FieldListDeclaration ::=
                "field_list" FieldListName "{"
                    FieldListEntries
                "}"
// [ field_list_entry ; ] +
    //todo
    syntax FieldListEntries ::= FieldListEntry ";" | FieldListEntries FieldListEntries

    //syntax FieldListEntry ::= ObjectRef | FieldValue
    syntax FieldListEntry ::= FieldRef | HeaderRef | FieldValue | FieldListName | "payload"


endmodule

module CHECKSUM-SYNTAX
imports HEADER-SYNTAX
    syntax FieldListCalculationName ::= Id
    syntax StreamFunctionAlgorithmName ::= Id
// 3 Checksums and Hash-value generators
   syntax FieldListCalculationDeclaration ::=
            "field_list_calculation" FieldListCalculationName "{"
                "input" "{"
                    FieldListNames
                "}"
                "algorithm" ":" StreamFunctionAlgorithmName ";"
                //"output_width" ":" ConstExpr ";"
                "output_width" ":" ConstValue ";"
            "}"
    //todo: non-empty list
    syntax FieldListNames ::= FieldListName | FieldListNames FieldListNames

// 3.1 Checksums
    syntax CalculatedFieldDeclaration ::= "calculated_field" FieldRef "{" UpdateVerifySpecs "}"

    syntax UpdateVerifySpecs ::= NeList{UpdateVerifySpec,""}

    syntax UpdateVerifySpec ::= UpdateOrVerify FieldListCalculationName OptionalIfCond ";"
    syntax OptionalIfCond ::= None | IfCond

    syntax UpdateOrVerify ::= "update" | "verify"
    syntax IfCond ::= "if" "(" CalcBoolCond ")"
    syntax CalcBoolCond ::=
                  "valid" "(" HeaderOrFieldRef ")"
                | FieldRef "==" FieldRef

    syntax HeaderOrFieldRef ::= HeaderRef | FieldRef

endmodule