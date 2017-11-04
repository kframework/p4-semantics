// also checked manually

module SPEC
imports LANG

rule [loop-inv]:
<T>
    <k> @nextPacket => @end </k> //<k> @nextPacket => @nextPacket </k> does not work but I don't know why,
    <index> 0 </index>
    <reg> (R:Int) => _:Int </reg>
    <packet> _:List => _:List </packet>
    <packetout> _:List => _:List </packetout>
    <in>  _:PacketList => $nilPacketList  </in>
    <out> O1:PacketList => ?O2:PacketList  </out>
</T>
requires        (R ==Int 1 andBool (#onPort(O1, 0) ==Int #onPort(O1, 1)) )
         orBool (R ==Int 0 andBool (#onPort(O1,0) ==Int (#onPort(O1,1) +Int 1)))
ensures absInt(#onPort(?O2,0) -Int #onPort(?O2,1)) <=Int 1



rule [loop-inv]:
<T>
    <k> @start => @end </k>
    <index> 0 </index>
    <reg> 1 => _:Int </reg>
    <packet> _:List => _:List </packet>
    <packetout> _:List => _:List </packetout>
    <in>  _:PacketList => $nilPacketList  </in>
    <out> $nilPacketList => ?O2:PacketList  </out>
</T>
ensures absInt(#onPort(?O2,0) -Int #onPort(?O2,1)) <=Int 1



endmodule
