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

//    syntax Id ::= "a" [token]  | "b" [token]
//    syntax Bool ::= "#wellDefined" "(" EntryList ")" [function,smtlib(smt_welldef)]
//    rule #wellDefined($nilEntryList) => true
//    rule #wellDefined($consEntryList($rule(_,_,@rcall(X:Id,_)), _)) => (X ==K a) orBool (X ==K b)
//    rule #wellDefined($consEntryList($rule(_,_,@apref(_)), _)) => false
//
//    syntax Int ::= "#egressToInt" "(" Val ")" [function,smtlib(egress_to_int)]
//    rule #egressToInt(@undef) => -1
//    rule #egressToInt(@val(V:Int,_,_)) => V

   //currenty wellDef* is defined for program simpler.{p4,impp} but can be easily generalized
   syntax Id ::= "a" [token]  | "b" [token]
   syntax Bool ::= "#wellDefTable" "(" EntryList ")" [function]//,smtlib(smt_welldef_table)]
   rule #wellDefTable ( $nilEntryList ) => true                                                 //[smt-lemma]
   rule #wellDefTable ( $consEntryList (R, E) ) => #wellDefRule(R) andBool #wellDefTable(E)     //[smt-lemma]

   syntax Bool ::= "#wellDefRule" "(" Rule ")" [function]//,smtlib(smt_welldef_rule)]
   //rule #wellDefRule(R) => R ==K $rule(?_,$ctr(@cons(@val(?_,8,false),@nil)),@rcall(?X:Id,$rv(?Vs:Vals))) andBool ((?X ==K b andBool ?Vs ==K @nil ) orBool (?X ==K a andBool ?Vs ==K @cons(@val(?_,8,false),@nil)))
   rule #wellDefRule ($rule(_,$ctr(@nil),_)) => false   //[smt-lemma]
   //rule #wellDefRule ($rule(_,$ctr(@cons(@val(_,8,false),@nil)),RC:RuleActionCallOrActionProfileRef)) => #wellDefRCall(RC)
   //rule #wellDefRule ($rule(_,$ctr(@cons(@val(_,W:Int,S:Bool),@nil)),_)) => false when W =/=Int 8 orBool S =/=Bool false
   rule #wellDefRule ($rule(_,$ctr(@cons(@val(_,W:Int,S:Bool),@nil)),RC:RuleActionCallOrActionProfileRef)) => (W ==Int 8) andBool (S ==Bool false) andBool (#wellDefRCall(RC)) //[smt-lemma]
   rule #wellDefRule ($rule(_,$ctr(@cons(_,@cons(_,_))),_)) => false //[smt-lemma]

   syntax Bool ::= "#wellDefDefaultAction" "(" DefaultEntry ")" [function]//,smtlib(smt_welldef_defaultaction)]
   rule #wellDefDefaultAction($nothing) => true //[smt-lemma]
   rule #wellDefDefaultAction(RC:RuleActionCallOrActionProfileRef) => #wellDefRCall(RC)// [smt-lemma]

   syntax Bool ::= "#wellDefRCall" "(" RuleActionCallOrActionProfileRef ")" [function]//,smtlib(smt_welldef_rcall)]
   rule #wellDefRCall(@apref(_)) => false   //[smt-lemma]
   rule #wellDefRCall(@rcall(X:Id,$rv(Vs:Vals))) => (X ==K b andBool Vs ==K @nil) orBool (X ==K a andBool #wellDefaArg(Vs)) //[smt-lemma]

   syntax Bool ::= "#wellDefaArg" "(" Vals ")" [function]//,smtlib(smt_welldef_aarg)]
   rule #wellDefaArg(@nil) => false //[smt-lemma]
   rule #wellDefaArg(@cons(_,@cons(_,_))) => false //[smt-lemma]
   //rule #wellDefaArg(@cons(@val(_,8,false),@nil)) => true //TODO: check the value ?
   //rule #wellDefaArg(@cons(@val(_,W:Int,S:Bool),@nil)) => false when W =/=Int 8 orBool S =/=Bool false //TODO: is this neccessary?
   rule #wellDefaArg(@cons(@val(_,W:Int,S:Bool),@nil)) => (W ==Int 8) andBool (S ==Bool false) //[smt-lemma]


   syntax Bool ::= "#noUndefPacket" "(" Vals ")" [function, smtlib(no_undef_packet)]
   rule #noUndefPacket(@nil) => true    [smt-lemma]
   rule #noUndefPacket(@cons(V:Val,Vs:Vals)) => (V ==K @val(?A:Int,?B:Int,?C:Bool)) andBool #noUndefPacket(Vs) [smt-lemma]
   //z3 can not prove using the following lemmas!
   //rule #noUndefPacket(@cons(@val(_,_,_),R)) => #noUndefPacket(R) [smt-lemma]
   //rule #noUndefPacket(@cons(@undef,_)) => false    [smt-lemma]

   syntax Bool ::= "#noUndefPacketList" "(" PacketList ")" [function]
   rule #noUndefPacketList($nilPacketList) => true
   rule #noUndefPacketList($consPacketList($packet(Vs,_),R)) => #noUndefPacket(Vs) andBool #noUndefPacketList(R)


   syntax Int ::= "#egressVal2Int" "(" Val ")" [function, smtlib(egress_to_int)]
   rule #egressVal2Int ( @undef ) => -1  [smt-lemma]
   rule #egressVal2Int (@val(I:Int,_,_)) => I  [smt-lemma]
endmodule