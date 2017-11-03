

module SPEC
imports LANG

rule
<T>
    <k> @nextPacket => @nextPacket </k>
    <index> 0 </index>
    <reg> 1 => 0 </reg>
    <packet> .List => _ </packet>
    <packetout> .List => _ </packetout>
    <in>  $consPacketList($packet(P:List,10) ,  L:PacketList) => L  </in>
    <out> $nilPacketList => $consPacketList($packet(P,0) , $nilPacketList)  </out>
</T>




endmodule
