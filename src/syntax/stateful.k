module STATEFUL-SYNTAX
// 7.1 Counters
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



// 7.2 Meters

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