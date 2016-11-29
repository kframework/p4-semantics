require "action-syntax.k"


module TABLE

endmodule

module TABLE-SYNTAX
imports ACTION-PROFILE-SYNTAX //for ActionSpecification, ConstValue, BoolValue, HeaderRef, FieldRef
    syntax TableName ::= Id
//11 Table Declarations
    syntax TableDeclaration ::=
            "table" TableName "{"
                //OptionalReads
                TableActions
                TableOptionals
                //OptionalMinSize
                //OptionalMaxSize
                //OptionalSize
                //OptionalSupportTimeout
            "}"
            | "table" TableName "{"
                              Reads
                              TableActions
                              TableOptionals
              "}"

    //TODO Note: current workraround for problem with None. note that this is not the official syntax, but it can be turned into semantic check insteaf of syntactic check
    syntax TableOptionals ::= List{TableOptional,""} [klabel('TableOptionals)]
    syntax TableOptional ::=
                  "min_size" ":" ConstValue ";"
                | "max_size" ":" ConstValue ";"
                | "size" ":" ConstValue ";"
                | "support_timeout" ":" BoolValue ";"



    //syntax OptionalReads ::= None | "reads" "{" FieldMatchs "}"
    syntax Reads ::= "reads" "{" FieldMatchs "}"


    syntax FieldMatchs ::= NeList{FieldMatch,""}                    [klabel('FieldMatchs)]

    //syntax OptionalMinSize ::= None |  "min_size" ":" ConstValue ";"
    //syntax OptionalMaxSize ::= None |  "max_size" ":" ConstValue ";"
    //syntax OptionaSize ::= None |  "size" ":" ConstValue ";" //already defined in action-profile-syntax
    //syntax OptionalSupportTimeout ::= None | "support_timeout" ":" BoolValue ";"

    syntax FieldMatch ::= FieldOrMaskedRef ":" FieldMatchType ";"
    syntax FieldOrMaskedRef ::= HeaderRef | FieldRef | FieldRef "mask" ConstValue

    syntax FieldMatchType ::=
                  "exact"
                 | "ternary"
                 | "lpm"
                 | "range"
                 | "valid"

    syntax TableActions ::= ActionSpecification | ActionProfileSpecification


    syntax ActionProfileSpecification ::= "action_profile" ":" ActionProfileName ";"
    //syntax ActionProfileSpecification ::= "action_profile" ":" ActionProfileName
    //TODO ISSUE does it have semi-colon or not?


endmodule