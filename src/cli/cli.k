require "../p4/p4-semantics.k"


module CLI-COMMON
imports INT
imports ID
imports LIST

    syntax Val
    syntax ActionCall

    syntax CLIIntList ::= List{Int, ","}
    syntax CLITableMatches ::= List{CLITableMatch, ""}
    syntax CLITableMatch ::= Int | pairInt(Int, Int)
    syntax CLIActionCall ::= Id "(" CLIIntList ")"

    syntax CLITestCommands ::= List{CLITestCommand, ""}
    syntax CLITestCommand ::=
                           "@setdefault" Id CLIActionCall
                         | "@add" Id CLITableMatches CLIActionCall
                         | "@packet" Int String
                         | "@expect"


    syntax CLIPgm ::= CLITestCommands

endmodule

module CLI-SYNTAX
imports CLI-COMMON

endmodule

module CLI-SEMANTICS
imports CLI-COMMON
imports P4-SEMANTICS

    configuration
        <p4/>
        <CLI>
            <cli-k> @loadP4Program($PGM:P4Program) ~> $CLI:CLIPgm </cli-k>
            <cli-out> .List </cli-out>
            <cli-rid> 0 </cli-rid>
        </CLI>

    syntax KItem ::= "@loadP4Program" "(" P4Program ")"
    rule <cli-k> (@loadP4Program(Program) => .K) ... </cli-k>
         <k> _ => @runP4Program(Program) </k>


    syntax List ::= #intList2ValList(CLIIntList) [function]
    rule #intList2ValList(I:Int, R:CLIIntList) => ListItem(@val(I, 0, false)) #intList2ValList(R)
    rule     #intList2ValList(.CLIIntList)         => .List

    rule    <cli-k> (@setdefault Table:Id Action:Id (Args:CLIIntList)  Rest:CLITestCommands) => Rest </cli-k>
            <p4>
                <table>
                    <t-name> Table </t-name>
                    <default> _ => @call(Action, $resolved(#intList2ValList(Args))) </default>
                    ...
                </table>
                <exec-mode> RUNNING </exec-mode>
                ...
            </p4>

    syntax List ::= #CLITableMatches2List(CLITableMatches) [function]
    rule #CLITableMatches2List(I:Int           R:CLITableMatches) => ListItem(@val(I, 0, false))                               #CLITableMatches2List(R)
    rule #CLITableMatches2List(pairInt(I1, I2) R:CLITableMatches) => ListItem($pair(@val(I1, 0, false), @val(I2, 0, false)))   #CLITableMatches2List(R)
    rule #CLITableMatches2List(.CLITableMatches)                  => .List

    rule    <cli-k> (@add Table:Id Matches:CLITableMatches Action:Id (Args:CLIIntList)  Rest:CLITestCommands) => Rest </cli-k>
            <cli-rid> RID:Int => RID +Int 1 </cli-rid>
            <p4>
                <table>
                    <t-name> Table </t-name>
                    <rules> _:List
                            (.List => ListItem($rule(
                                RID,
                                $ctr(#CLITableMatches2List(Matches)),
                                @call(Action, $resolved(#intList2ValList(Args)))))
                            )
                    </rules>
                    ...
                </table>
                <exec-mode> RUNNING </exec-mode>
                ...
            </p4>

    rule    <cli-k> (@packet Port:Int Payload:String Rest:CLITestCommands) => Rest </cli-k>
            <p4>
                <in> _:List (.List => ListItem($packet(Payload, Port))) </in>
                ...
            </p4>

//    rule    <cli-k> (@sympacket Rest:CLITestCommands) => Rest </cli-k>
//                <p4>
//                    <in> _:List (.List => ListItem($packet(?L:List, ?I:Int))) </in>
//                    ...
//                </p4>

    rule    <cli-k> (@expect Rest:CLITestCommands) => Rest </cli-k>
            <cli-out> _:List (.List => ListItem(Packet)) </cli-out>
            <p4>
                <out>  (ListItem(Packet) => .List) _:List </out>
                ...
            </p4>


endmodule