require "../p4/p4-semantics.k"


module NETWORK-COMMON
imports ID
imports LIST
imports INT

    syntax P4Program
    syntax P4NodeProgram ::= "node" String "{" P4Program "}"
    syntax P4NodePrograms ::= NeList{P4NodeProgram, ""}
    syntax NodePort ::= nodePort(Id, Int)
    syntax P4NetworkProgram ::= P4NodePrograms

endmodule

module NETWORK-SYNTAX
imports NETWORK-COMMON
imports P4-SYNTAX

endmodule

module NETWORK-SEMANTICS
imports NETWORK-COMMON
imports P4-SEMANTICS

    configuration
        <network-programs> $NPGM:P4NetworkProgram  </network-programs>
        <topology> .Map </topology>
        <nodes>
            <node multiplicity="*" type="Set">
                <nodeId> "" </nodeId>
                <p4/>
            </node>
        </nodes>

    rule <network-programs> node N:String { Program:P4Program } Rest:P4NodePrograms => Rest </network-programs>
         <nodes>
            (.Bag => <node>
                        <nodeId> N </nodeId>
                        <p4>
                            <k> @runP4Program(Program)  </k>
                            ...
                        </p4>
                        ...
                     </node>
            )
            ...
         </nodes>

    // A workaround for the spurious node created due to the way the configuration is defined
//    rule <network-programs> .P4NodePrograms => .K </network-programs>
//         <nodes>
//            (<node>
//                <nodeId> "" </nodeId>
//                ...
//             </node> => .Bag)
//            ...
//         </nodes>

endmodule