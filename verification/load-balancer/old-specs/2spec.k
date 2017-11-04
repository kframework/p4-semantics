
module SPEC
  imports P4-SEMANTICS

  syntax Id ::= "reg" [token] | "reg_val" [token] | "meta" [token]

rule
<T>
    <k> @nextPacket => @nextPacket </k>
    <instances>
        <instance>
            <name> standard_metadata </name>
            <fieldVals> _:Map => _:Map </fieldVals>
        </instance>
        <instance>
            <name> meta </name>
            <fieldVals> reg_val |-> (@val ( 0 , 8 , false ) => @val ( 1 , 8 , false )) </fieldVals>
        </instance>
    </instances>
    <statefuls>
        <stateful>
            <name> reg </name>
            <vals> .Map => (0 |-> @val(1,8,false)) </vals>
        </stateful>
    </statefuls>
    <ctx> <frameStack> .List => _ </frameStack> <crnt> .Map => _ </crnt> </ctx>
    <packet> . => _ </packet>
    <packetout> .List => _ </packetout>
    <parser>
        <pctx>
            <index> 0 => _ </index>
            <lastExt> . => _ </lastExt>
            <varWidth> . => _ </varWidth>
            <packetSize> . => _ </packetSize>
        </pctx>
    </parser>
    <buffer>
        <in> ListItem($packet(.List,10)) => .List </in>
        <out> .List => ListItem($packet(.List,0))  </out>
    </buffer>
</T>

endmodule
