require "value-syntax.k"
//require "table-syntax.k"
//require "stateful-syntax.k"
require "parser-syntax.k"
require "header-syntax.k"
//require "control-syntax.k"

// based on P4 Language Spec Version 1.0.3 Nov. 2016

module P4-COMMON
    imports VALUE-SYNTAX
    imports HEADER-SYNTAX
   // imports STATEFUL-SYNTAX
   // imports CHECKSUM-SYNTAX
    imports PARSER-SYNTAX
    //imports PARSER-EXCEPTION-SYNTAX
    //imports ACTION-SYNTAX
    //imports ACTION-PROFILE-SYNTAX
    //imports TABLE-SYNTAX
    //imports CONTROL-SYNTAX

    syntax P4Program ::= P4Declarations

    syntax P4Declarations ::= NeList{P4Declaration,""}  [klabel('P4Declarations)]


    syntax P4Declaration ::=
                  HeaderTypeDeclaration
                | InstanceDeclaration
    //            | FieldListDeclaration
    //            | FieldListCalculationDeclaration
    //            | CalculatedFieldDeclaration
    //            | ValueSetDeclaration
                | ParserFunctionDeclaration
    //            | ParserExceptionDeclaration
    //            | CounterDeclaration
    //            | MeterDeclaration
    //            | RegisterDeclaration
    //            | ActionFunctionDeclaration
    //            | ActionProfileDeclaration
    //            | ActionSelectorDeclaration
    //            | TableDeclaration
    //            | ControlFunctionDeclaration*/


endmodule

module P4-SYNTAX
    imports P4-COMMON

        syntax BinaryValueToken ::= r"(0b|0B)[0-1\\_]+" [token, notInRules, klabel('BinaryValueToken)] //Token{("0b" | "0B")[0-1\\_]+} [notInRules]
        syntax DecimalValueToken ::= r"[0-9\\_]+" [token, notInRules, klabel('DecimalValueToken)] //Token{[0-9\\_]+} [notInRules]
        syntax HexadecimalValueToken ::= r"(0x|0X)[0-9a-fA-F\\_]+" [token, notInRules, klabel('HexadecimalValueToken)] //Token{("0x" | "0X")[0-9a-fA-F\\_]+} [notInRules]

endmodule