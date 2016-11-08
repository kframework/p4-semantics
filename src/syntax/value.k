module VALUE-SYNTAX
// 1.5.1 Value Specifications
    syntax ConstValue ::= OptionalSign OptionalWidthSpec UnsignedValue

    syntax OptionalWidthSpec ::= None | WidthSpec
    syntax OptionalSign ::= None | Sign

    syntax Sign ::= "+" | "-"

    syntax UnsignedValue ::= BinaryValue | DecimalValue | HexadecimalValue

    syntax BoolValue ::= "true" | "false"

    syntax _BinaryValue ::= Token{("0b" | "0B")[0-9]+} [notInRules]
    syntax _DecimalValue ::= Token{[0-9_]+} [notInRules]
    syntax _HexadecimalValue ::= Token{("0x" | "0X")[0-9]+} [notInRules]

    syntax BinaryValue ::= _BinaryValue
    syntax DecimalValue ::= _DecimalValue
    syntax HexadecimalValue ::= _HexadecimalValue

    syntax WidthSpec ::= _DecimalValue "'"

    // The node field_value is used in this specification to emphasize that the width of the representation may be relevant;
    syntax FieldValue ::= ConstValue



// Optionally, the bit-width of the value may be specified as indicated by bit_width. Zero is permitted as a width which is the same as not specifying a width. If no width pre- cedes the value, then the width is inferred. For positive values the inferred width is the smallest number of bits required to contain the value. For negative values the inferred width is one more than the smallest number of bits required to contain the positive value.


endmodule
