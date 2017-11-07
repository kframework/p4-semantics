module COMMON
    //=========
    syntax Bool ::= vars(List)
    //========


    syntax Val ::= "@val" "("Int","Int","Bool")" //int,width,signed

    syntax Vals ::= "@nil"
                    | "@cons" "(" Val "," Vals ")"


    //syntax ActionCall ::= "@call" "(" ActionName "," K /* ResolvedArgs */ ")" [strict(2)]
    syntax ActionCall ::= "@call" "(" Id "," ResolvedArgs /* ResolvedArgs */ ")"
    syntax ActionProfileEntryRef ::= "@apref" "(" Int ")"
    syntax ActionCallOrActionProfileRef ::= ActionCall | ActionProfileEntryRef


    syntax ResolvedArgs ::= "$resolved" "(" List ")"
    syntax KResult ::= ResolvedArgs

    syntax KResult ::= "$pair" "(" Val "," Val ")"


    syntax Rule ::= "$rule" "(" Int /* Id */ "," Criteria "," ActionCallOrActionProfileRef ")"
    syntax Criteria ::= "$ctr" "(" List ")"

    syntax PacketData ::= List //| String
    syntax Packet ::= "$packet" "(" PacketData "," Int ")" //[smtlib(smt_packet)]

    syntax PacketList ::=
                           "$nilPacketList" [smtlib(nil_packst_list)]
                         | "$consPacketList" "(" Packet "," PacketList ")" [smtlib(cons_packet_list)]

endmodule