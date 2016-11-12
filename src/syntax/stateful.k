require "table.k"

module STATEFUL

endmodule

module STATEFUL-SYNTAX
imports TABLE-SYNTAX //forst ConstValue TableName FieldRef
    syntax CounterName ::= Id
    syntax MeterName ::= Id
    syntax RegisterName ::= Id
// 7.1 Counters
    syntax CounterDeclaration ::=
                    "counter" CounterName "{"
                        "type" ":" CounterType ";"
                        OptionalDirectOrStatic
                        OptionalInstantCount
                        OptionalMinWidth
                        OptionalSaturating
                    "}"
    syntax OptionalDirectOrStatic ::= None |  DirectOrStatic ";"
    //syntax OptionalInstantCount ::= None | "instance_count" ":" ConstExpr ";"
    //syntax OptionalMinWidth ::= None | "min_width" ":" ConstExpr ";"
    //TODO ISSUE: what is ConstExpr? For now, assuming it is ConstValue
    syntax OptionalInstantCount ::= None | "instance_count" ":" ConstValue ";"
    syntax OptionalMinWidth ::= None | "min_width" ":" ConstValue ";"

    syntax OptionalSaturating ::= None | "saturating" ";"

    syntax CounterType ::= "bytes" | "packets" | "bytes_and_packets"
    syntax DirectOrStatic ::= DirectAttribute | StaticAttribute
    syntax DirectAttribute ::= "direct" ":" TableName
    syntax StaticAttribute ::= "static" ":" TableName



// 7.2 Meters

    syntax MeterDeclaration ::=
            "meter" MeterName "{"
                "type" ":" MeterType ";"
                OptionalResult
                OptionalDirectOrStatic
                OptionalInstantCount
            "}"

    syntax OptionalResult ::= None | "result" ":" FieldRef ";"
    //syntax OptionalInstantCount ::= None | "instance_count" ":" ConstExpr ";"
    //TODO ISSUE: what is ConstExpr? For now, assuming it is ConstValue
    syntax OptionalInstantCount ::= None | "instance_count" ":" ConstValue ";"

    syntax MeterType ::= "bytes" | "packets"


// 7.3 Registers

    syntax RegisterDeclaration ::=
            "register" RegisterName "{"
                //WidthOrLayout ";"
                WidthDeclaration ";"
                OptionalDirectOrStatic
                OptionalInstantCount
                OptionalAttributeList
            "}"

    syntax OptionalAttributeList ::= None | AttributeList ";"

    syntax WidthDeclaration ::= "width" ":" ConstValue
    syntax AttributeList ::= "attributes" ":" AttrEntry

    syntax AttrEntry ::= "signed" | "saturated" | AttrEntry "," AttrEntry

endmodule