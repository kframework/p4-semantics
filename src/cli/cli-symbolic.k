require "cli.k"


module CLI-SYMBOLIC-COMMON
imports CLI-COMMON

    syntax CLITestCommand ::= "@sympacket"

    syntax CLITestCommand ::= "@sympacket" Int "-" SymPacketFields
    syntax SymPacketFields ::= NeList{SymPacketField, ""}
    syntax SymPacketField ::= "*" | SymOrInt":"Int
    syntax SymOrInt ::= "?" | Int
endmodule

module CLI-SYMBOLIC-SYNTAX
imports CLI-SYMBOLIC-COMMON

endmodule

module CLI-SYMBOLIC-SEMANTICS
imports CLI-SYMBOLIC-COMMON
imports CLI-SEMANTICS

    rule    <cli-k> (@sympacket Rest:CLITestCommands) => Rest </cli-k>
            <p4>
                <in> _:List (.List => ListItem($packet(?_L:List, ?_I:Int))) </in>
                ...
            </p4>


    rule <cli-k> (.K => @sympacketFileds2List(Fields, .List)) ~> (@sympacket _:Int - Fields  _:CLITestCommands)  </cli-k>

    syntax KIteme ::= "@sympacketFileds2List" "(" SymPacketFields "," List ")"
    rule <cli-k> @sympacketFileds2List((*             R) => R, _:List (.List => ?_L:List)                         ) ... </cli-k>
    rule <cli-k> @sympacketFileds2List((I:Int : W:Int R) => R, _:List (.List => ListItem(@val(I,      W, false))) ) ... </cli-k>
    rule <cli-k> @sympacketFileds2List((? : W:Int     R) => R, _:List (.List => ListItem(@val(?_I:Int, W, false)))) ... </cli-k>
    rule <cli-k> @sympacketFileds2List(.SymPacketFields, L) => L ... </cli-k>

    rule <cli-k> (L:List ~> @sympacket P:Int - _  Rest:CLITestCommands) => Rest  </cli-k>
         <p4>
            <in> _:List (.List => ListItem($packet(L, P))) </in>
            ...
         </p4>


endmodule

