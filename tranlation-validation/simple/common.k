module COMMON
    //=========
    syntax Bool ::= vars(List)
    //========


    syntax Val ::= "@val" "("Int","Int","Bool")" [smtlib(smt_val)] //int,width,signed

    syntax Vals ::= "@nil"                         [smtlib(smt_nil_vals)]
                    | "@cons" "(" Val "," Vals ")" [smtlib(smt_cons_vals)]


    //syntax ActionCall ::= "@call" "(" ActionName "," K /* ResolvedArgs */ ")" [strict(2)]
    syntax ActionCall ::= "@call" "(" Id "," ResolvedArgs /* ResolvedArgs */ ")"
    syntax ActionProfileEntryRef ::= "@apref" "(" Int ")"
    syntax ActionCallOrActionProfileRef ::= ActionCall | ActionProfileEntryRef
    syntax DefaultEntry ::= ActionCallOrActionProfileRef | "$nothing"

    syntax ResolvedArgs ::= "$resolved" "(" Vals ")"
    syntax KResult ::= ResolvedArgs

    syntax KResult ::= "$pair" "(" Val "," Val ")"


    syntax Rule ::= "$rule" "(" Int /* Id */ "," Criteria "," ActionCallOrActionProfileRef ")"
    syntax Criteria ::= "$ctr" "(" Vals ")"

    syntax PacketData ::= Vals //| String
    syntax Packet ::= "$packet" "(" Vals "," Int ")" //[smtlib(smt_packet)]

    syntax PacketList ::=
                           "$nilPacketList" [smtlib(nil_packst_list)]
                         | "$consPacketList" "(" Packet "," PacketList ")" [smtlib(cons_packet_list)]

    syntax EntryList ::=
                           "$nilEntryList" [smtlib(nil_entry_list)]
                         | "$consEntryList" "(" Rule "," EntryList ")" [smtlib(cons_entry_list)]
endmodule