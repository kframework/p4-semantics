

module SPEC
imports LANG

rule
<T>
    <k> @nextPacket => @nextPacket </k>
    <index> 0 </index>
    <reg> 1 => 0 </reg>
    <packet> .List => _ </packet>
    <packetout> .List => _ </packetout>
    <in>  $consPacketList($packet(P:List,_:Int) ,  Lin:PacketList) => Lin  </in>
    <out> Lout:PacketList => $consPacketList($packet(P,0) , Lout)  </out>
</T>




endmodule
