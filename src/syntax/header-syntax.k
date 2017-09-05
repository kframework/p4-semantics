require "value-syntax.k"

module HEADER

endmodule

module HEADER-SYNTAX
imports VALUE-SYNTAX
    syntax HeaderTypeName ::= Id
    syntax InstanceName ::= Id
    syntax FieldName ::= Id
    syntax FieldListName ::= Id

// 2.1 HeaderTypeDeclarations
    syntax HeaderTypeDeclaration ::= "header_type" HeaderTypeName "{" HeaderDecBody "}"

    //syntax HeaderDecBody ::= "fields" "{" FieldDecs "}" OptionalLengthDec OptionalMaxLengthDec
    syntax HeaderDecBody ::=
              "fields" "{" FieldDecs "}"  HeaderOptionals              [klabel('HeaderDecBody)]
//            | "fields" "{" FieldDecs "}" LengthDec      [klabel('HeaderDecBodyLen)]
//            | "fields" "{" FieldDecs "}" MaxLengthDec   [klabel('HeaderDecBodyMaxLen)]
//            | "fields" "{" FieldDecs "}" LengthDec MaxLengthDec [klabel('HeaderDecBodyLenMaxLen)]


    //TODO Note: current workraround for problem with None. note that this is not the official syntax, but it can be turned into semantic check instead of syntactic check
    syntax HeaderOptionals ::= List{HeaderOptional,""} [klabel('HeaderOptionals)]
    syntax HeaderOptional ::= LengthDec | MaxLengthDec

    //length is in bytes
    //The length attribute specifies an expression whose evaluation gives the length of the header in bytes for variable length headers.
    // It must be present if the header has variable length
    //syntax OptionalLengthDec ::= None | "length" ":" LengthExp ";"  //TODO ISSUE: why lengthexp here and constvalue for the other one?
    syntax LengthDec ::= "length" ":" LengthExp ";"
    // If, at run time, the calculated length exceeds this value, it is considered a parser exception.
    //syntax OptionalMaxLengthDec ::= None | "max_length" ":" ConstValue ";"
    syntax MaxLengthDec ::= "max_length" ":" ConstValue ";"

    syntax FieldDecs ::= NeList{FieldDec,""}                [klabel('FieldDecs)]
    //syntax FieldDec ::= FieldName ":" BitWidth OptionalFieldMods ";"
    syntax FieldDec ::=
              FieldName ":" BitWidth ";"
            | FieldName ":" BitWidth  "(" FieldMods ")" ";"

    //syntax OptionalFieldMods ::= None | "(" FieldMods ")"
    syntax FieldMods ::= NeList{FieldMod, ","}              [klabel('FieldMods)]
    syntax FieldMod ::= "signed" | "saturating"
    //syntax LengthBinOp ::= "+" | "-" | "*" | "<<" | ">>" //priorities according to C
    syntax LengthExp ::=
                  ConstValue
                | FieldName //what does it mean? reference to a field whose runtime value we will use
                //| LengthExp LengthBinOp LengthExp
                | "(" LengthExp ")"         [bracket]
                |  LengthExp "*" LengthExp   [strict,left,klabel(LenExpMult), prefer]
                >
                  LengthExp "+" LengthExp   [strict,left, klabel(LenExpPlus), prefer]
                | LengthExp "-" LengthExp   [strict,left, klabel(LenExpMinus), prefer]
                >
                  LengthExp "<<" LengthExp   [strict,left, klabel(LenExpShftL), prefer]
                | LengthExp ">>" LengthExp   [strict,left, klabel(LenExpShftR), prefer]

    syntax BitWidth ::= ConstValue | "*"


// 2.2 HeaderandMetadataInstances
    syntax InstanceDeclaration ::= HeaderInstance | MetadataInstance
    syntax HeaderInstance ::= ScalarInstance | ArrayInstance
    syntax ScalarInstance ::= "header" HeaderTypeName InstanceName ";"
    syntax ArrayInstance ::= "header" HeaderTypeName InstanceName "[" ConstValue "]" ";"

    syntax MetadataInstance ::=
                       "metadata" HeaderTypeName  InstanceName ";"
                    //|  "metadata" HeaderTypeName  InstanceName OptionalMetadataInitializer //TODO ISSUE: not sure about the syntax
                      | "metadata" HeaderTypeName  InstanceName MetadataInitializer
    //If an initializer is present,the named fields are initialized to the indicated values;  unspecified values are initialized to 0.
    //ISSUE: what if inilializer is not specified? ANSWER: will init to zero by default

    //syntax OptionalMetadataInitializer ::= None | MetadataInitializer


    syntax MetadataInitializer ::= "{" FieldValueAssignments "}"

    syntax FieldValueAssignments ::= NeList{FieldValueAssignment,""}    [klabel('FieldValueAssignments)]
    syntax FieldValueAssignment ::= FieldName ":" FieldValue ";"    [klabel('FieldValAsgn)]


// 2.3 HeaderandFieldReferences
    syntax HeaderRef ::=
              InstanceName
            | InstanceName "[" Index "]" [strict(2)]

    syntax Index ::= ConstValue | "last"

    syntax FieldRef ::= HeaderRef "." FieldName


endmodule


module CHECKSUM-SYNTAX
imports HEADER-SYNTAX
    syntax FieldListCalculationName ::= Id
    syntax StreamFunctionAlgorithmName ::= Id
// 2.4 FieldLists
    syntax FieldListDeclaration ::=
                "field_list" FieldListName "{"
                    FieldListEntryItems
                "}"
    syntax FieldListEntryItems ::= NeList{FieldListEntryItem,""}        [klabel('FieldListEntryItems)]
    syntax FieldListEntryItem ::= FieldListEntry ";"                    [klabel('FieldListEntryItem)]

    //syntax FieldListEntry ::= ObjectRef | FieldValue
    syntax FieldListEntry ::=     FieldRef
                                | HeaderRef
                                | FieldValue
                                | FieldListName     [klabel('FieldListEntryListName)]
                                | "payload"
    //The identifier payload indicates that the contents of the packet following the header of the previously mentioned field is included in the field list
    //TODO ISSUE: what if no field was previously mentioned? what does previously exactly mean?


// 3 Checksums and Hash-value generators
   syntax FieldListCalculationDeclaration ::=
            "field_list_calculation" FieldListCalculationName "{"
                "input" "{"
                    FieldListNameItems
                "}"
                "algorithm" ":" StreamFunctionAlgorithmName ";"
                "output_width" ":" ConstValue ";"
            "}"
    syntax FieldListNameItems ::= NeList{FieldListNameItem,""}          [klabel('FieldListNameItems)]
    syntax FieldListNameItem ::= FieldListName ";"                      [klabel('FieldListNameItem)]


// 3.1 Checksums
    //Note that although this declaration may occur anywhere in the P4 program, the decla- ration should be placed immediately after the header instance declaration for the field referenced.
    syntax CalculatedFieldDeclaration ::=
            "calculated_field" FieldRef "{"
                UpdateVerifySpecs
            "}"

    syntax UpdateVerifySpecs ::= NeList{UpdateVerifySpec,""}            [klabel('UpdateVerifySpecs)]

    //syntax UpdateVerifySpec ::= UpdateOrVerify FieldListCalculationName OptionalIfCond ";"
    syntax UpdateVerifySpec ::=
              UpdateOrVerify FieldListCalculationName  ";"
            | UpdateOrVerify FieldListCalculationName IfCond ";"

    //syntax OptionalIfCond ::= None | IfCond

    syntax UpdateOrVerify ::= "update" | "verify"
    syntax IfCond ::= "if" "(" CalcBoolCond ")"
    syntax CalcBoolCond ::=
                  "valid" "(" HeaderOrFieldRef ")"  [klabel(CalcBCValid)]
                | FieldRef "==" FieldValue          [klabel(CalcBCEq)]

    syntax HeaderOrFieldRef ::= HeaderRef | FieldRef

endmodule
