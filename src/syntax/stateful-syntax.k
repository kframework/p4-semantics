require "table-syntax.k"

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
                        StatefulOptionals
                        CounterOptionals
    //                    OptionalDirectOrStatic
    //                    OptionalInstantCount
    //                    OptionalMinWidth
    //                    OptionalSaturating
                    "}"
    //syntax OptionalDirectOrStatic ::= None |  DirectOrStatic ";"
    //syntax OptionalInstantCount ::= None | "instance_count" ":" ConstExpr ";"
    //syntax OptionalMinWidth ::= None | "min_width" ":" ConstExpr ";"
    //TODO ISSUE: what is ConstExpr? For now, assuming it is ConstValue
    //syntax OptionalInstantCount ::= None | "instance_count" ":" ConstValue ";"
    //syntax OptionalMinWidth ::= None | "min_width" ":" ConstValue ";"
    //syntax OptionalSaturating ::= None | "saturating" ";"

    syntax CounterOptionals ::= List{CounterOptional,""} [klabel('CounterOptionals)]
    syntax CounterOptional ::=
//                      DirectOrStatic ";"                [klabel('CODirectOrStatic)]
//                    | InstantCount ";"                  [klabel('COInstanceCount)]
                      "min_width" ":" ConstValue ";"
                    | "saturating" ";"


    syntax CounterType ::=
                          "bytes"       [klabel(CTBytes), symbol]
                        | "packets"     [klabel(CTPackets), symbol]
                        | "bytes_and_packets"
    syntax DirectOrStatic ::= DirectAttribute | StaticAttribute
    syntax DirectAttribute ::= "direct" ":" TableName
    syntax StaticAttribute ::= "static" ":" TableName

    syntax InstantCount ::= "instance_count" ":" ConstValue


    syntax StatefulOptionals ::= List{StatefulOptional, ""} [klabel('StatefulOptionals)]
    syntax StatefulOptional ::=
                          DirectOrStatic ";"
                        | InstantCount ";"


// 7.2 Meters

    syntax MeterDeclaration ::=
            "meter" MeterName "{"
                "type" ":" MeterType ";"
                MeterOptionals
                StatefulOptionals
                //OptionalResult
                //OptionalDirectOrStatic
                //OptionalInstantCount
            "}"

    //syntax OptionalResult ::= None | "result" ":" FieldRef ";"
    //syntax OptionalInstantCount ::= None | "instance_count" ":" ConstExpr ";"
    //TODO ISSUE: what is ConstExpr? For now, assuming it is ConstValue
    //syntax OptionalInstantCount ::= None | "instance_count" ":" ConstValue ";"

    syntax MeterOptionals ::= List{MeterOptional,""} [klabel('MeterOptionals)]
    syntax MeterOptional ::=
                          "result" ":" FieldRef ";"
//                        | DirectOrStatic ";"        [klabel('MODirectOrStatic)]
//                        | InstantCount ";"          [klabel('MOInstanceCount)]


    syntax MeterType ::=  "bytes"       [klabel(MTBytes), token]
                        | "packets"     [klabel(MTPackets), token]


// 7.3 Registers

    syntax RegisterDeclaration ::=
            "register" RegisterName "{"
                WidthDeclaration ";"
                StatefulOptionals
                RegisterOptionals
                //OptionalDirectOrStatic
                //OptionalInstantCount
                //OptionalAttributeList
            "}"

    //syntax OptionalAttributeList ::= None | AttributeList ";"

    syntax RegisterOptionals ::= List{RegisterOptional,""} [klabel('RegisterOptionals)]
    syntax RegisterOptional ::=
//                          DirectOrStatic ";"        [klabel('RODirectOrStatic)]
//                        | InstantCount ";"          [klabel('ROInstanceCount)]
                           AttributeList ";"

    syntax WidthDeclaration ::= "width" ":" ConstValue
    syntax AttributeList ::= "attributes" ":" AttrEntries

    syntax AttrEntries ::= List{AttrEntry,","} [klabel('AttrEntries)]
    syntax AttrEntry ::=
                      "signed"      [klabel(StatefulSigned)]
                    | "saturating"  [klabel(StatefulSaturating)]
                    //| AttrEntry "," AttrEntry

endmodule