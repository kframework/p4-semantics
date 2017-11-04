

module SPEC
imports LANG

rule
<T>
    <k> @nextPacket => @nextPacket </k>
    <index> 0 </index>
    //<reg> R1:Int => ?R2:Int </reg>
    <reg> R1:Int </reg>
    <packet> .List => _ </packet>
    <packetout> .List => _ </packetout>
    <in>  $consPacketList($packet(P1:List,_:Int) , $consPacketList($packet(P2:List,_:Int) ,  Lin:PacketList)) => Lin  </in>
    <out> Lout:PacketList => $consPacketList($packet(P2,R1) , $consPacketList($packet(P1,?R2:Int) , Lout))  </out>
    //<out> Lout:PacketList => $consPacketList($packet(P,0) , Lout)  </out>
</T>
//requires //absInt(#onPort(Lout,0) -Int #onPort(Lout,1)) <=Int 1

requires (R1 ==Int 1 orBool R1 ==Int 0)
         //andBool absInt(#onPort(Lout,0) -Int #onPort(Lout,1)) <=Int 1
ensures  (?R2 ==Int 1 orBool ?R2 ==Int 0)

//ensures
//        andBool
//                    #onPort($consPacketList($packet(P,R2), Lout),0) -Int #onPort($consPacketList($packet(P,R2), Lout),1))) ==Int 1


rule
<T>
    <k> @start => @end </k>
    <index> 0 </index>
    //<reg> R1:Int => ?R2:Int </reg>
    <reg> 1 => _ </reg>
    <packet> .List => _ </packet>
    <packetout> .List => _ </packetout>
    <in>  Lin:PacketList => $nilPacketList  </in>
    <out> $nilPacketList => ?Lout:PacketList  </out>

</T>
//ensures absInt(#onPort(?Lout, 0) -Int #onPort(?Lout,1)) <=Int 1


endmodule
