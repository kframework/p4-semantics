module COMMON
    //=========
    syntax Bool ::= vars(List)
    //========

    syntax Val ::= "@undef" [smtlib(val_undef)]
    syntax Val ::= "@val" "("Int","Int","Bool")" [smtlib(smt_val)] //int,width,signed

    syntax Vals ::= "@nil"                         [smtlib(smt_nil_vals)]
                    | "@cons" "(" Val "," Vals ")" [smtlib(smt_cons_vals)]


    //syntax ActionCall ::= "@call" "(" ActionName "," K /* ResolvedArgs */ ")" [strict(2)]
    syntax RuleActionCall ::= "@rcall" "(" Id "," ResolvedVals /* ResolvedArgs */ ")"
    syntax ActionProfileEntryRef ::= "@apref" "(" Int ")"
    syntax RuleActionCallOrActionProfileRef ::= RuleActionCall | ActionProfileEntryRef
    syntax DefaultEntry ::= RuleActionCallOrActionProfileRef | "$nothing"

    syntax ResolvedVals ::= "$rv" "(" Vals ")"
    syntax KResult ::= ResolvedVals

    syntax KResult ::= "$pair" "(" Val "," Val ")"


    syntax Rule ::= "$rule" "(" Int /* Id */ "," Criteria "," RuleActionCallOrActionProfileRef ")"
    syntax Criteria ::= "$ctr" "(" Vals ")"

    syntax PacketData ::= Vals //| String
    syntax Packet ::= "$packet" "(" Vals "," Int ")" //[smtlib(smt_packet)]

    syntax PacketList ::=
                           "$nilPacketList" [smtlib(nil_packst_list)]
                         | "$consPacketList" "(" Packet "," PacketList ")" [smtlib(cons_packet_list)]

    syntax EntryList ::=
                           "$nilEntryList" [smtlib(nil_entry_list)]
                         | "$consEntryList" "(" Rule "," EntryList ")" [smtlib(cons_entry_list)]

    syntax Id ::= "a" [token]  | "b" [token]
    syntax Bool ::= "#wellDefined" "(" EntryList ")" [function,smtlib(smt_welldef)]
    rule #wellDefined($nilEntryList) => true
    rule #wellDefined($consEntryList($rule(_,_,@rcall(X:Id,_)), _)) => (X ==K a) orBool (X ==K b)
    rule #wellDefined($consEntryList($rule(_,_,@apref(_)), _)) => false

    syntax Int ::= "#egressToInt" "(" Val ")" [function,smtlib(egress_to_int)]
    rule #egressToInt(@undef) => -1
    rule #egressToInt(@val(V:Int,_,_)) => V
endmodule