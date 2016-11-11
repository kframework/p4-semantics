module VALUE

endmodule

module VALUE-SYNTAX
syntax None ::= ""
// 1.5.1 Value Specifications
    syntax ConstValue ::= OptionalSign OptionalWidthSpec UnsignedValue

    syntax OptionalWidthSpec ::= None | WidthSpec
    syntax OptionalSign ::= None | Sign

    syntax Sign ::= "+" | "-"

    syntax UnsignedValue ::= BinaryValue | DecimalValue | HexadecimalValue

    syntax BoolValue ::= "true" | "false"

    syntax BinaryValueToken ::= r"(0b|0B)[0-1\\_]+" [token, notInRules] //Token{("0b" | "0B")[0-1\\_]+} [notInRules]
    syntax DecimalValueToken ::= r"[0-9\\_]+" [token, notInRules] //Token{[0-9\\_]+} [notInRules]
    syntax HexadecimalValueToken ::= r"(0x|0X)[0-9a-fA-F\\_]+" [token, notInRules] //Token{("0x" | "0X")[0-9a-fA-F\\_]+} [notInRules]

    syntax BinaryValue ::= BinaryValueToken
    syntax DecimalValue ::= DecimalValueToken
    syntax HexadecimalValue ::= HexadecimalValueToken

    syntax WidthSpec ::= DecimalValueToken "'"

    // The node field_value is used in this specification to emphasize that the width of the representation may be relevant;
    syntax FieldValue ::= ConstValue



// Optionally, the bit-width of the value may be specified as indicated by bit_width. Zero is permitted as a width which is the same as not specifying a width. If no width pre- cedes the value, then the width is inferred. For positive values the inferred width is the smallest number of bits required to contain the value. For negative values the inferred width is one more than the smallest number of bits required to contain the positive value.


endmodule
