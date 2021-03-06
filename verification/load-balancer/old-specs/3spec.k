
module SPEC
  imports P4-SEMANTICS

  syntax Id ::= "meta_t" [token] | "reg_val" [token] | "meta" [token] | "reg" [token] | "balance" [token] | "read_reg" [token] | "port" [token] | "val" [token] | "ingress" [token]

rule
<T>
    <k> @nextPacket => @nextPacket </k>
    <headers>... HEADERS:Bag ...</headers>
    <arrays> .Map </arrays>
    <fieldLists>... FIELDLISTS:Bag ...</fieldLists>
    <fieldListCalcs>... FIELDLISTCALCS:Bag ...</fieldListCalcs>
    <calcFields>... CALCFIELDS:Bag ...</calcFields>
    <instances>
        <instance>
            <valid> true </valid>
            <metadata> true </metadata>
            <typeName> %standard_metadata_t </typeName>
            <name> standard_metadata </name>
            <fieldVals> ingress_port |-> @undef egress_spec |-> @undef </fieldVals>
        </instance>
        <instance>
            <valid> true </valid>
            <metadata> true </metadata>
            <typeName> meta_t </typeName>
            <name> meta </name>
            <fieldVals> reg_val |-> @val ( 0 , 8 , false ) =>  reg_val |-> @val ( 1 , 8 , false )</fieldVals>
        </instance>
    </instances>
    <initInstances>... INITINSTANCES:Bag ...</initInstances>
    <initArrays> .Map </initArrays>
    <parserStates>
        <state> <name> start </name> <body> .ExtractOrSetStatements return ingress ; </body> </state>
    </parserStates>
    <valueSets>... VALUESETS:Bag ...</valueSets>
    <exceptionHandlers>... EXCEPTIONHANDLERS:Bag ...</exceptionHandlers>
    <handledExceptions> .Set </handledExceptions>
    <statefuls>
        <stateful>
            <stype> $register </stype>
            <name> reg </name>
            <opts> "$instant_count" |-> 1 "$saturating" |-> false "$signed" |-> false "$binding" |-> $static_global </opts>
            <vals> .Map => (0 |-> @val(1,8,false)) </vals>
            <width> 8 </width>
        </stateful>
    </statefuls>
    <tableDirects> .Map </tableDirects>
    <actions>... ACTIONS:Bag ...</actions>
    <actionProfiles>... ACTIONPROFILES:Bag ...</actionProfiles>
    <actionSelectors>... ACTIONSELECTORS:Bag  ...</actionSelectors>
    <tables>
        <table>
            <name> balance_table </name>
            <reads> ( meta . reg_val ) : exact ;  .FieldMatchs </reads>
            <acts> actions { balance ;  .ActionNameItems } </acts>
            <opts> .TableOptionals </opts>
            <rules> ListItem ( $rule ( 0 , $ctr ( ListItem ( @val ( 0 , 0 , false ) ) ) , @call ( balance , $resolved ( ListItem ( @val ( 0 , 0 , false ) ) ListItem ( @val ( 1 , 0 , false ) ) ) ) ) ) ListItem ( $rule ( 1 , $ctr ( ListItem ( @val ( 1 , 0 , false ) ) ) , @call ( balance , $resolved ( ListItem ( @val ( 1 , 0 , false ) ) ListItem ( @val ( 0 , 0 , false ) ) ) ) ) ) </rules>
            <default> . </default>
        </table>
        <table>
            <name> read_reg_table </name>
            <reads> meta . valid : exact ;  .FieldMatchs </reads>
            <acts> actions { read_reg ;  .ActionNameItems } </acts>
            <opts> .TableOptionals </opts>
            <rules> ListItem ( $rule ( 0 , $ctr ( ListItem ( @val ( 1 , 0 , false ) ) ) , @call ( read_reg , $resolved ( .List ) ) ) ) </rules>
            <default> . </default>
        </table>
    </tables>
    <controlFlows>
        <control> <name> ingress </name> <body> apply ( read_reg_table ) { .HitMissCases }  ( apply ( balance_table ) { .HitMissCases }  .ControlStatements ) </body> </control>
    </controlFlows>
    <cfset> SetItem ( ingress ) </cfset>
    <calcFieldSet> .Set </calcFieldSet>
    <ctx> <frameStack> .List => _ </frameStack> <crnt> .Map => _ </crnt> </ctx>
    <packet> . => _ </packet>
    <packetout> .List => _ </packetout>
    <parser>
        <graph>
            <onpath> .Set </onpath>
            <marked> <mstates> SetItem ( start ) </mstates> <mheaders> .Set </mheaders> </marked>
            <dporder> .List </dporder>
        </graph>
        <pctx> <index> 0 => _ </index> <lastExt> . => _ </lastExt> <varWidth> . => _ </varWidth> <packetSize> . => _ </packetSize> </pctx>
    </parser>
    <buffer>
        <in> ListItem($packet(.List,10)) => .List </in>
        <out> .List => ListItem($packet(.List,0))  </out>
    </buffer>
</T>

endmodule
