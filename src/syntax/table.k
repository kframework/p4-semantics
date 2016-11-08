module TABLE-SYNTAX
//11 Table Declarations
    syntax TableDeclaration ::=
            "table" TableName "{"
                OptionalReads
                TableActions
                OptionalSize
                OptionalSupportTimeout
            "}"

    syntax OptionalReads ::= None | "reads" "{" FieldMatchs "}"

    //todo
    syntax FieldMatchs ::= FieldMatch | FieldMatchs FieldMatchs

    //syntax OptionalSize ::= None |  Size ":" ConstExpr ";"
    syntax OptionalSize ::= None |  Size ":" ConstValue ";"
    syntax Size ::= "min_size" | "max_size" | "size"

    syntax OptionalSupportTimeout ::= "support_timeout" ":" BoolValue ";"

    syntax FieldMatch ::= FieldOrMaskedRef ":" FieldMatchType ";"
    syntax FieldOrMaskedRef ::= HeaderRef | FieldRef | FieldRef "mask" ConstExpr

    syntax FieldMatchType ::=
                  "exact"
                 | "ternary"
                 | "lpm"
                 //| "index"
                 | "range"
                 | "valid"

    syntax TableActions ::= ActionSpecification | ActionProfileSpecification

    syntax ActionSpecification ::= "actions" "{" ActionNames "}"
    //todo
    syntax ActionNames ::= ActionName | ActionNames ActionNames

    //syntax ActionProfileSpecification ::= "action_profile" ":" ActionProfileName ";"
    syntax ActionProfileSpecification ::= "action_profile" ":" ActionProfileName


endmodule