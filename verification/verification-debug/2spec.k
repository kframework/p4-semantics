

module SPEC
imports LANG

rule
<T>
    <k> @nextPacket => @nextPacket </k>
    <index> 0 </index>
    <reg> R1:Int => ?R2:Int </reg>
    //<reg> 1 => 0 </reg>
    <packet> .List => _ </packet>
    <packetout> .List => _ </packetout>
    <in>  $consPacketList($packet(P:List,_:Int) ,  Lin:PacketList) => Lin  </in>
    <out> Lout:PacketList => $consPacketList($packet(P,R2) , Lout)  </out>
    //<out> Lout:PacketList => $consPacketList($packet(P,0) , Lout)  </out>
</T>
//requires //absInt(#onPort(Lout,0) -Int #onPort(Lout,1)) <=Int 1
//requires R1 ==Int 1 orBool R1 ==Int 0
//ensures ?R2 ==Int 1 orBool ?R2 ==Int 0



endmodule
