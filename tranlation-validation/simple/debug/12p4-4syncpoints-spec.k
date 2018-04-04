
module P4-SPEC
  imports P4-SEMANTICS

syntax Id ::= "h_t" [token] | "h1" [token] | "f1" [token] | "n" [token] | "f2" [token]| "ingress" [token] | "t" [token] | "a" [token] | "b" [token]

//rule
//<L1>
//   <k>@exec</k>
//   <headers>
//      <header>
//         <name>%standard_metadata_t</name>
//         <opts>.Map</opts>
//          <fields> ingress_port : #token("32","DecimalValueToken@VALUE-SYNTAX") ( .FieldMods ) ;  ( egress_spec : #token("32","DecimalValueToken@VALUE-SYNTAX") ( .FieldMods ) ;  .FieldDecs ) </fields>
//      </header>
//      <header>
//         <name>h_t</name>
//         <opts>"$fixed_width" |-> 16</opts>
//         <fields>f1 : #token("8","DecimalValueToken@VALUE-SYNTAX") ( .FieldMods ) ;  ( f2 : #token("8","DecimalValueToken@VALUE-SYNTAX") ( .FieldMods ) ;  .FieldDecs )</fields>
//      </header>
//   </headers>
//   <arrays>.Map</arrays>
//   <fieldLists>.Bag</fieldLists>
//   <fieldListCalcs>.Bag</fieldListCalcs>
//   <calcFields>.Bag</calcFields>
//   <instances>
//      <instance>
//         <valid>true</valid>
//         <metadata>true</metadata>
//         <typeName>%standard_metadata_t</typeName>
//         <name>standard_metadata</name>
//         <fieldVals>ingress_port |-> _:Val egress_spec |-> _:Val </fieldVals>
//      </instance>
//      <instance>
//         <valid>false</valid>
//         <metadata>false</metadata>
//         <typeName>h_t</typeName>
//         <name>h1</name>
//         <fieldVals>.Map</fieldVals>
//      </instance>
//   </instances>
//   <initInstances> INITINSTANCES </initInstances>
//   <initArrays>.Map</initArrays>
//   <parserStates>
//      <state>
//         <name>start</name>
//         <body>( extract ( h1 ) ; .ExtractOrSetStatements ) return ingress ;</body>
//      </state>
//   </parserStates>
//   <valueSets>.Bag </valueSets>
//   <exceptionHandlers>.Bag </exceptionHandlers>
//   <handledExceptions>.Set</handledExceptions>
//   <statefuls>.Bag</statefuls>
//   <tableDirects>.Map</tableDirects>
//   <actions>
//      <action>
//         <name>b</name>
//         <params>.ParamList</params>
//         <body>modify_field ( ( standard_metadata . egress_spec ) , ( #token("2","DecimalValueToken@VALUE-SYNTAX") , .Args ) ) ;  .ActionStatements</body>
//      </action>
//      <action>
//         <name>a</name>
//         <params>n , .ParamList</params>
//         <body>modify_field ( ( h1 . f2 ) , ( n , .Args ) ) ;  ( modify_field ( ( standard_metadata . egress_spec ) , ( #token("1","DecimalValueToken@VALUE-SYNTAX") , .Args ) ) ;  .ActionStatements )</body>
//      </action>
//   </actions>
//   <actionProfiles>.Bag</actionProfiles>
//   <actionSelectors>.Bag</actionSelectors>
//   <tables>
//      <table>
//         <name>t</name>
//         <reads>( h1 . f1 ) : exact ;  .FieldMatchs</reads>
//         <acts>actions { a ;  ( b ;  .ActionNameItems ) }</acts>
//         <opts>.TableOptionals</opts>
//         <rules> T:List </rules>
//         <default>.</default>
//      </table>
//   </tables>
//   <controlFlows>
//      <control>
//         <name>ingress</name>
//         <body>apply ( t ) { .HitMissCases }  .ControlStatements</body>
//      </control>
//   </controlFlows>
//   <cfset>SetItem ( ingress )</cfset>
//   <calcFieldSet>.Set</calcFieldSet>
//   <ctx>
//      <frameStack>.List</frameStack>
//      <crnt>("$rule" |-> (_:K)) ("$table" |-> (_:K)) ("$action" |-> (_:K)) ("$miss" |-> (_:K))</crnt>
//   </ctx>
//   <packet> _:List </packet>
//   <packetout> _:List </packetout>
//   <parser>
//      <graph>
//         <onpath>.Set</onpath>
//         <marked>
//            <mstates>SetItem ( start )</mstates>
//            <mheaders>SetItem ( h1 )</mheaders>
//         </marked>
//         <dporder>ListItem ( h1 )</dporder>
//      </graph>
//      <pctx>
//         <index>0</index>
//         <lastExt> _</lastExt>
//         <varWidth> _</varWidth>
//         <packetSize> _</packetSize>
//      </pctx>
//   </parser>
//   <buffer>
//      <in> L:PacketList </in>
//      <out>@nilPacketList</out>
//   </buffer>
//</L1>
//ensures vars(ListItem(L) ListItem(T))


//start of execution (p0)
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
         <fieldVals>ingress_port |-> @undef egress_spec |-> @undef </fieldVals>
      </instance>
      <instance>
         <valid>false</valid>
         <metadata>false</metadata>
         <typeName>h_t</typeName>
         <name>h1</name>
         <fieldVals>.Map</fieldVals>
      </instance>
   </instances>
   <initInstances>
      .Bag
   </initInstances>
   <insts>ListItem ( h1 ) ListItem ( standard_metadata )</insts>
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
         <rules> T:EntryList </rules>
         <default> D:DefaultEntry </default>
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
   <packet> _ </packet>
   <packetout> _ </packetout>
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
      <in> I:PacketList </in>
      <out>$nilPacketList</out>
   </buffer>
</L1>
requires #wellDefTable(T) andBool #wellDefDefaultAction(D) andBool #noUndefPacketList(I)
ensures vars(ListItem(I) ListItem(T) ListItem(D))

//loop over packets (p1)
rule
<L1>
   <k>@nextPacket</k>
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
         <valid>_</valid>
         <metadata>false</metadata>
         <typeName>h_t</typeName>
         <name>h1</name>
         <fieldVals> _:Map </fieldVals>
      </instance>
   </instances>
   <initInstances>
      <instance>
         <valid>true</valid>
         <metadata>true</metadata>
         <typeName>%standard_metadata_t</typeName>
         <name>standard_metadata</name>
         <fieldVals>ingress_port |-> @undef egress_spec |-> @undef </fieldVals>
      </instance>
      <instance>
         <valid>false</valid>
         <metadata>false</metadata>
         <typeName>h_t</typeName>
         <name>h1</name>
         <fieldVals>.Map</fieldVals>
      </instance>
   </initInstances>
   <insts>ListItem ( h1 ) ListItem ( standard_metadata )</insts>
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
         <rules> T:EntryList </rules>
         <default> D:DefaultEntry </default>
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
   <packet> _:Vals </packet>
   <packetout> _:Vals </packetout>
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
         <index>_</index>
         <lastExt> _</lastExt>
         <varWidth> _</varWidth>
         <packetSize> _</packetSize>
      </pctx>
   </parser>
   <buffer>
      <in> I:PacketList </in>
      <out>O:PacketList</out>
   </buffer>
</L1>
requires #wellDefTable(T) andBool #wellDefDefaultAction(D) andBool #noUndefPacketList(I) andBool #noUndefPacketList(O)
ensures vars(ListItem(T) ListItem(I) ListItem(O) ListItem(D))

//experience: the order of elements in cell fragments (e.g instances)  must be the same (associative matching does not work in this case)

//loop over entries (p2)
rule
<L1>
   <k>@checkNextRule ( ( h1 . f1 ) : exact ;  .FieldMatchs , C:EntryList ) ~> @setCrnt ( "$table" , . ) ~> @checkNextAppSelCase ( .HitMissCases ) ~> .ControlStatements ~> @egress ~> @txenPacket ~> @nextPacket</k>
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
         <fieldVals>ingress_port |-> @val ( _ , 32 , false ) egress_spec |-> E:Val </fieldVals>
      </instance>
      <instance>
         <valid>true</valid>
         <metadata>false</metadata>
         <typeName>h_t</typeName>
         <name>h1</name>
         //<fieldVals>f2 |-> @val ( F1:Int , 8 , false ) f1 |-> @val ( F2:Int , 8 , false )</fieldVals> //we don't check width during extraction for packets given using @vals
         <fieldVals>f2 |-> @val ( F1:Int , _ , _ ) f1 |-> @val ( F2:Int , _ , _ )</fieldVals>
      </instance>
   </instances>
   <initInstances>
      <instance>
         <valid>true</valid>
         <metadata>true</metadata>
         <typeName>%standard_metadata_t</typeName>
         <name>standard_metadata</name>
         <fieldVals>ingress_port |-> @undef egress_spec |-> @undef </fieldVals>
      </instance>
      <instance>
         <valid>false</valid>
         <metadata>false</metadata>
         <typeName>h_t</typeName>
         <name>h1</name>
         <fieldVals>.Map</fieldVals>
      </instance>
   </initInstances>
   <insts>ListItem ( h1 ) ListItem ( standard_metadata )</insts>
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
         <rules> T:EntryList </rules>
         <default> D:DefaultEntry </default>
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
   <packet> PL:Vals </packet>
   <packetout> @nil </packetout>
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
         <index>_</index>
         <lastExt> _</lastExt>
         <varWidth> _</varWidth>
         <packetSize> _</packetSize>
      </pctx>
   </parser>
   <buffer>
      <in> I:PacketList </in>
      <out>O:PacketList</out>
   </buffer>
</L1>
//ListItem(#egressToInt(E))
requires #wellDefTable(T) andBool #wellDefDefaultAction(D) andBool #wellDefTable(C) andBool #noUndefPacketList(I) andBool #noUndefPacketList(O) andBool #noUndefPacket(PL)
ensures vars(ListItem(I) ListItem(O) ListItem(T) ListItem(C) ListItem(F1) ListItem(F2) ListItem(E) ListItem(D))


//end (p3)
rule
<L1>
   <k>@end</k>
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
         <valid>_</valid>
         <metadata>false</metadata>
         <typeName>h_t</typeName>
         <name>h1</name>
         <fieldVals>_</fieldVals>
      </instance>
   </instances>
   <initInstances> _ </initInstances>
   <insts>ListItem ( h1 ) ListItem ( standard_metadata )</insts>
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
         <rules> _ </rules>
         <default> _ </default>
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
   <packet> _</packet>
   <packetout> _ </packetout>
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
         <index>_</index>
         <lastExt> _</lastExt>
         <varWidth> _</varWidth>
         <packetSize> _</packetSize>
      </pctx>
   </parser>
   <buffer>
      <in> $nilPacketList </in>
      <out> O:PacketList </out>
   </buffer>
</L1>
ensures vars(ListItem(O) ListItem(0))
[trusted]
endmodule









