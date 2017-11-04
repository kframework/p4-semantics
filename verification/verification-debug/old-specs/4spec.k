

module SPEC
imports LANG

rule
<T>
    <k> @nextPacket => @end </k> //<k> @nextPacket => @nextPacket </k> does not work but I don't know why,
    <index> 0 </index>
    <reg> (R1:Int) => ?R2:Int </reg>
    <packet> _:List => _:List </packet>
    <packetout> _:List => _:List </packetout>
    <in>  _:PacketList => $nilPacketList  </in>
    <out> Lout:PacketList => ?Lout2:PacketList  </out>
</T>
requires R1 ==Int 1 orBool R1 ==Int 0
ensures ?R2 ==Int 0 orBool ?R2 ==Int 1
//requires //absInt(#onPort(Lout,0) -Int #onPort(Lout,1)) <=Int 1

//requires (R1 ==Int 1 orBool R1 ==Int 0)
         //andBool absInt(#onPort(Lout,0) -Int #onPort(Lout,1)) <=Int 1
//ensures  (?R2 ==Int 1 orBool ?R2 ==Int 0)

//ensures
//        andBool
//                    #onPort($consPacketList($packet(P,R2), Lout),0) -Int #onPort($consPacketList($packet(P,R2), Lout),1))) ==Int 1


//rule
//<T>
//    <k> @start => @end </k>
//    <index> 0 </index>
//    //<reg> R1:Int => ?R2:Int </reg>
//    <reg> 1 => _ </reg>
//    <packet> .List => _ </packet>
//    <packetout> .List => _ </packetout>
//    <in>  Lin:PacketList => $nilPacketList  </in>
//    <out> $nilPacketList => ?Lout:PacketList  </out>
//
//</T>
//ensures absInt(#onPort(?Lout, 0) -Int #onPort(?Lout,1)) <=Int 1


endmodule
