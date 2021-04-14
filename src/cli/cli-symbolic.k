require "cli.k"


module CLI-SYMBOLIC-COMMON
imports CLI-COMMON

    syntax CLITestCommand ::= "@sympacket"

endmodule

module CLI-SYMBOLIC-SYNTAX
imports CLI-SYMBOLIC-COMMON

endmodule

module CLI-SYMBOLIC-SEMANTICS
imports CLI-SYMBOLIC-COMMON
imports CLI-SEMANTICS

    rule    <cli-k> (@sympacket Rest:CLITestCommands) => Rest </cli-k>
            <p4>
                <in> _:List (.List => ListItem($packet(?L:List, ?I:Int))) </in>
                ...
            </p4>
endmodule