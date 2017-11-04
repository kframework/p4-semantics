
module SPEC
  imports P4-SEMANTICS

  syntax Id ::= "meta_t" [token] | "reg_val" [token] | "meta" [token] | "reg" [token] | "balance" [token] | "read_reg" [token] | "port" [token] | "val" [token] | "ingress" [token]

rule [loop-inv]:
<T>
    <k> @nextPacket => @end </k>
    <headers>
        <header>
            <name> %standard_metadata_t </name>
            <opts> .Map </opts>
            <fields> ingress_port : #token("32","DecimalValueToken@VALUE-SYNTAX") ( .FieldMods ) ;  ( egress_spec : #token("32","DecimalValueToken@VALUE-SYNTAX") ( .FieldMods ) ;  .FieldDecs ) </fields>
            </header>
        <header>
            <name> meta_t </name>
            <opts> "$fixed_width" |-> 8 </opts>
            <fields> reg_val : #token("8","DecimalValueToken@VALUE-SYNTAX") ( .FieldMods ) ;  .FieldDecs </fields>
            </header>
        </headers>
    <arrays> .Map </arrays>
    <fieldLists> .Bag </fieldLists>
    <fieldListCalcs> .Bag </fieldListCalcs>
    <calcFields> .Bag </calcFields>
    <instances>
        <instance>
            <valid> true </valid>
            <metadata> true </metadata>
            <typeName> %standard_metadata_t </typeName>
            <name> standard_metadata </name>
            <fieldVals> ingress_port |-> (_:Val => _:Val) egress_spec |-> (_:Val => _:Val) </fieldVals>
        </instance>
        <instance>
            <valid> true </valid>
            <metadata> true </metadata>
            <typeName> meta_t </typeName>
            <name> meta </name>
            <fieldVals> reg_val |-> @val ( 0 => _:Int , 8 , false ) </fieldVals>
        </instance>
    </instances>
    <initInstances> INITINSTANCES </initInstances>

    <initArrays> .Map </initArrays>
    <parserStates>
        <state> <name> start </name> <body> .ExtractOrSetStatements return ingress ; </body> </state>
    </parserStates>
    <valueSets> .Bag </valueSets>
    <exceptionHandlers> .Bag </exceptionHandlers>
    <handledExceptions> .Set </handledExceptions>
    <statefuls>
        <stateful>
            <stype> $register </stype>
            <name> reg </name>
            <opts> "$instant_count" |-> 1 "$saturating" |-> false "$signed" |-> false "$binding" |-> $static_global </opts>
            <vals> (0 |-> @val(R:Int => _:Int,8,false)) </vals>
            <width> 8 </width>
        </stateful>
    </statefuls>
    <tableDirects> .Map </tableDirects>
    <actions>
        <action>
            <name> balance </name>
            <params> port , ( val , .ParamList ) </params>
            <body> modify_field ( ( standard_metadata . egress_spec ) , ( port , .Args ) ) ;  ( register_write ( reg , ( #token("0","DecimalValueToken@VALUE-SYNTAX") , ( val , .Args ) ) ) ;  .ActionStatements ) </body>
        </action>
        <action>
            <name> read_reg </name>
            <params> .ParamList </params>
            <body> register_read ( ( meta . reg_val ) , ( reg , ( #token("0","DecimalValueToken@VALUE-SYNTAX") , .Args ) ) ) ;  .ActionStatements </body>
        </action>
    </actions>
    <actionProfiles> .Bag </actionProfiles>
    <actionSelectors> .Bag </actionSelectors>
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
    <ctx>
        <frameStack> .List => _ </frameStack>
        <crnt> ("$rule" |-> (_:K => _:K)) ("$table" |-> (_:K => _:K)) ("$action" |-> (_:K => _:K)) ("$miss" |-> (_:K => _:K))</crnt>
    </ctx>
    <packet> _:List => _:List </packet>
    <packetout> _:List => _:List </packetout>
    <parser>
        <graph>
            <onpath> .Set </onpath>
            <marked> <mstates> SetItem ( start ) </mstates> <mheaders> .Set </mheaders> </marked>
            <dporder> .List </dporder>
        </graph>
        <pctx> <index> 0 => _ </index> <lastExt> _ => _ </lastExt> <varWidth> _ => _ </varWidth> <packetSize> _ => _ </packetSize> </pctx>
    </parser>
    <buffer>
        <in>  _:PacketList => $nilPacketList  </in>
        <out> O1:PacketList => ?O2:PacketList  </out>
    </buffer>
</T>
requires        (R ==Int 1 andBool (#onPort(O1, 0) ==Int #onPort(O1,1) +Int 1))
         orBool (R ==Int 0 andBool (#onPort(O1,0) ==Int (#onPort(O1,1))))
ensures absInt(#onPort(?O2,0) -Int #onPort(?O2,1)) <=Int 1
endmodule
