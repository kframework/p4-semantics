
module P4-SPEC
  imports P4-SEMANTICS

syntax Id ::= "h_t" [token] | "h1" [token] | "f1" [token] | "n" [token] | "f2" [token]| "ingress" [token] | "t" [token] | "a" [token] | "b" [token]

rule
<L1>
   <k>@exec</k>
   <headers>
      <header>
         <name>%standard_metadata_t</name>
         <opts>.Map</opts>
          <fields> ingress_port : #token("32","DecimalValueToken@VALUE-SYNTAX") ( .FieldMods ) ;  ( egress_spec : #token("32","DecimalValueToken@VALUE-SYNTAX") ( .FieldMods ) ;  .FieldDecs ) </fields>
      </header>
      <header>
         <name>h_t</name>
         <opts>"$fixed_width" |-> 16</opts>
         <fields>f1 : #token("8","DecimalValueToken@VALUE-SYNTAX") ( .FieldMods ) ;  ( f2 : #token("8","DecimalValueToken@VALUE-SYNTAX") ( .FieldMods ) ;  .FieldDecs )</fields>
      </header>
   </headers>
   <arrays>.Map</arrays>
   <fieldLists>.Bag</fieldLists>
   <fieldListCalcs>.Bag</fieldListCalcs>
   <calcFields>.Bag</calcFields>
   <instances>
      <instance>
         <valid>true</valid>
         <metadata>true</metadata>
         <typeName>%standard_metadata_t</typeName>
         <name>standard_metadata</name>
         <fieldVals>ingress_port |-> _:Val egress_spec |-> _:Val </fieldVals>
      </instance>
      <instance>
         <valid>false</valid>
         <metadata>false</metadata>
         <typeName>h_t</typeName>
         <name>h1</name>
         <fieldVals>.Map</fieldVals>
      </instance>
   </instances>
   <initInstances> INITINSTANCES </initInstances>
   <initArrays>.Map</initArrays>
   <parserStates>
      <state>
         <name>start</name>
         <body>( extract ( h1 ) ; .ExtractOrSetStatements ) return ingress ;</body>
      </state>
   </parserStates>
   <valueSets>.Bag </valueSets>
   <exceptionHandlers>.Bag </exceptionHandlers>
   <handledExceptions>.Set</handledExceptions>
   <statefuls>.Bag</statefuls>
   <tableDirects>.Map</tableDirects>
   <actions>
      <action>
         <name>b</name>
         <params>.ParamList</params>
         <body>modify_field ( ( standard_metadata . egress_spec ) , ( #token("2","DecimalValueToken@VALUE-SYNTAX") , .Args ) ) ;  .ActionStatements</body>
      </action>
      <action>
         <name>a</name>
         <params>n , .ParamList</params>
         <body>modify_field ( ( h1 . f2 ) , ( n , .Args ) ) ;  ( modify_field ( ( standard_metadata . egress_spec ) , ( #token("1","DecimalValueToken@VALUE-SYNTAX") , .Args ) ) ;  .ActionStatements )</body>
      </action>
   </actions>
   <actionProfiles>.Bag</actionProfiles>
   <actionSelectors>.Bag</actionSelectors>
   <tables>
      <table>
         <name>t</name>
         <reads>( h1 . f1 ) : exact ;  .FieldMatchs</reads>
         <acts>actions { a ;  ( b ;  .ActionNameItems ) }</acts>
         <opts>.TableOptionals</opts>
         <rules> T:List </rules>
         <default>.</default>
      </table>
   </tables>
   <controlFlows>
      <control>
         <name>ingress</name>
         <body>apply ( t ) { .HitMissCases }  .ControlStatements</body>
      </control>
   </controlFlows>
   <cfset>SetItem ( ingress )</cfset>
   <calcFieldSet>.Set</calcFieldSet>
   <ctx>
      <frameStack>.List</frameStack>
      <crnt>("$rule" |-> (_:K)) ("$table" |-> (_:K)) ("$action" |-> (_:K)) ("$miss" |-> (_:K))</crnt>
   </ctx>
   <packet> _:List </packet>
   <packetout> _:List </packetout>
   <parser>
      <graph>
         <onpath>.Set</onpath>
         <marked>
            <mstates>SetItem ( start )</mstates>
            <mheaders>SetItem ( h1 )</mheaders>
         </marked>
         <dporder>ListItem ( h1 )</dporder>
      </graph>
      <pctx>
         <index>0</index>
         <lastExt> _</lastExt>
         <varWidth> _</varWidth>
         <packetSize> _</packetSize>
      </pctx>
   </parser>
   <buffer>
      <in> L:PacketList </in>
      <out>$nilPacketList</out>
   </buffer>
</L1>
ensures vars(ListItem(L) ListItem(T))
endmodule
