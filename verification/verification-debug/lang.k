module LANG

syntax Pgm ::= "@start"


//syntax Val ::= "@val" "("Int","Int","Bool")" //int,width,signed

//syntax Vals ::= "@nil"
//                | "@cons" "(" Val "," Vals ")"



//syntax PacketData ::= List [smtlib(smt_packetdata_list)] | String | Vals
syntax Packet ::= "$packet" "(" List "," Int ")" //[smtlib(smt_packet)]

syntax PacketList ::=
                       "$nilPacketList" [smtlib(nil_packst_list)]
                     | "$consPacketList" "(" Packet "," PacketList ")" [smtlib(cons_packet_list)]

syntax KItem ::= "@nextPacket"

configuration
<T>
    <k>  $PGM:Pgm </k>
    <in> $nilPacketList </in>
    <out> $nilPacketList </out>
    <packet> .List </packet>
    <packetout> .List </packetout>
    <reg> 1 </reg>
    <index> 0 </index>
</T>


rule @start => @nextPacket

syntax KItem ::= "@end"
rule <k> @nextPacket => @end </k>
     <in> $nilPacketList </in>

rule <k> @nextPacket => @changeReg ~> @addPayload ~> @txenPacket ~> @nextPacket </k>
     <in> $consPacketList($packet(Packet:List,Port:Int) , L:PacketList) => L </in>
     <packet> _:List => Packet </packet>

syntax KItem ::= "@changeReg"
rule <k> @changeReg => .K ...</k>
     <reg> 0 => 1 </reg>
rule <k> @changeReg => .K ...</k>
     <reg> 1 => 0 </reg>
rule <k> @changeReg => .K ...</k>
     <reg> P:Int => 3 </reg>
     when P =/=Int 0 andBool P=/=Int 1

syntax KItem ::= "@addPayload"
rule <k> @addPayload => .K ... </k>
     <packet> Packet:List  </packet>
     <packetout> _:List (.List => range(Packet, I ,0)) </packetout>
     <index> I:Int </index>
     when I <Int sizeList(Packet)
rule <k> @addPayload => .K ... </k>
     <packet> Packet:List  </packet>
     <index> I:Int </index>
     when I >=Int sizeList(Packet)

syntax KItem ::= "@txenPacket"
rule <k> @txenPacket => .K ...</k>
     <packetout> P:List => .List </packetout>
     <out>   L:PacketList => $consPacketList($packet(P,R) , L)  </out>
     <reg> R:Int </reg>


syntax Int ::= "#onPort" "(" PacketList "," Int ")" [function, smtlib(smt_on_port)]
rule #onPort($nilPacketList,_:Int) => 0
rule #onPort($consPacketList($packet(_,P:Int),L:PacketList), P) => 1 +Int #onPort(L, P)
rule #onPort($consPacketList($packet(_,P1:Int),L:PacketList), P2:Int) => #onPort(L, P2) when P1 =/=Int P2

endmodule
