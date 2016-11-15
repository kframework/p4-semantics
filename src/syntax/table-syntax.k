require "action-syntax.k"


module TABLE

endmodule

module TABLE-SYNTAX
imports ACTION-PROFILE-SYNTAX //for ActionSpecification, ConstValue, BoolValue, HeaderRef, FieldRef
    syntax TableName ::= Id
//11 Table Declarations
    syntax TableDeclaration ::=
            "table" TableName "{"
                OptionalReads
                TableActions
                OptionalMinSize
                OptionalMaxSize
                OptionalSize
                OptionalSupportTimeout
            "}"

    syntax OptionalReads ::= None | "reads" "{" FieldMatchs "}"

    syntax FieldMatchs ::= NeList{FieldMatch,""}                    [klabel('FieldMatchs)]

    syntax OptionalMinSize ::= None |  "min_size" ":" ConstValue ";"
    syntax OptionalMaxSize ::= None |  "max_size" ":" ConstValue ";"
    //syntax OptionaSize ::= None |  "size" ":" ConstValue ";" //already defined in action-profile-syntax
    syntax OptionalSupportTimeout ::= None | "support_timeout" ":" BoolValue ";"

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