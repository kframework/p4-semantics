require "../p4-semantics.k"


module STF-TEST-COMMON
imports ACTION-SYNTAX
imports INT


syntax STFTableMatches ::= List{STFTableMatch, ""}
syntax STFTableMatch ::= Id ":" UnsignedValue
syntax STFACtionCall ::= Id "(" Args ")"

syntax STFTestCommands ::= List{STFTestCommand, ""}
syntax STFTestCommand ::=
                       "setdefault" STFACtionCall
                     | "add" STFTableMatches STFACtionCall
                     | "packet" Int Int
                     | "expect" Int HexaDecimalString

syntax HexaDecimalString ::= HexaDecimalStringToken
syntax HexaDecimalStringToken [token]

syntax STFPgm ::= STFTestCommands

endmodule

module STF-TEST-SYNTAX
imports STF-TEST-COMMON
//imports P4-TOKEN-SYNTAX

//syntax HexaDecimalStringToken ::= r"[0-9a-fA-F\\ ]+" [token]
//syntax #Layout ::= r"(#[^\\n\\r]*)"     // "#"
//                 | r"([\\ \\n\\r\\t])"  // Whitespace
//                 | r"(//[^\\n\\r]*)"    // "//"

endmodule

module STF-TEST-SEMANTICS
imports STF-TEST-COMMON
imports P4-SEMANTICS

configuration
    <p4/>
    <stf>
        $STF:STFPgm
    </stf>

endmodule