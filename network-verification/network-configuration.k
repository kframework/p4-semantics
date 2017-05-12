require "../src/syntax/p4-syntax.k"

module P4-NETWORK-SYNTAX
    imports P4-NETWORK-COMMON

        syntax BinaryValueToken ::= r"(0b|0B)[0-1\\_]+" [token, notInRules, klabel('BinaryValueToken)] //Token{("0b" | "0B")[0-1\\_]+} [notInRules]
        syntax DecimalValueToken ::= r"[0-9\\_]+" [token, notInRules, klabel('DecimalValueToken)] //Token{[0-9\\_]+} [notInRules]
        syntax HexadecimalValueToken ::= r"(0x|0X)[0-9a-fA-F\\_]+" [token, notInRules, klabel('HexadecimalValueToken)] //Token{("0x" | "0X")[0-9a-fA-F\\_]+} [notInRules]

endmodule


module P4-NETWORK-COMMON
    imports VALUE-SYNTAX
    imports HEADER-SYNTAX
   // imports STATEFUL-SYNTAX //TODO
   // imports CHECKSUM-SYNTAX //TODO
    imports PARSER-SYNTAX
    //imports PARSER-EXCEPTION-SYNTAX //TODO
    imports ACTION-SYNTAX
    //imports ACTION-PROFILE-SYNTAX //TODO
    imports TABLE-SYNTAX
    imports CONTROL-SYNTAX

    syntax P4Program ::= P4Declarations

    syntax P4Declarations ::= NeList{P4Declaration,""}  [klabel('P4Declarations)]


    syntax P4Declaration ::=
                  HeaderTypeDeclaration
                | InstanceDeclaration
    //            | FieldListDeclaration //TODO
    //            | FieldListCalculationDeclaration //TODO
    //            | CalculatedFieldDeclaration //TODO
    //            | ValueSetDeclaration //TODO
                | ParserFunctionDeclaration
    //            | ParserExceptionDeclaration //TODO
    //            | CounterDeclaration //TODO
    //            | MeterDeclaration //TODO
    //            | RegisterDeclaration //TODO
                | ActionFunctionDeclaration
    //            | ActionProfileDeclaration //TODO
    //            | ActionSelectorDeclaration //TODO
                | TableDeclaration
                | ControlFunctionDeclaration


     syntax P4Programs ::= NeList{P4Program,"----"}         [klabel('P4Programs)]
endmodule

module CONFIGURATION
imports P4-NETWORK-COMMON



syntax KItem ::= "@init" | "@exec"
syntax KItem ::=  "@parseOrder" "(" K ")"
syntax Id ::= "start" [token]


syntax Val ::= "@val" "("Int","Int","Bool")" //int,width,signed
syntax ActionCall ::= "@call" "(" ActionName "," K /* ResolvedArgs */ ")" [strict(2)]

syntax ResolvedArgs ::= "$resolved" "(" List ")"
syntax KResult ::= ResolvedArgs


// --------------------init------------------------------------


syntax Rule ::= "$rule" "(" Criteria "," ActionCall ")"
syntax Criteria ::= "$ctr" "(" List ")"
syntax Packet ::= "$packet" "(" List "," Int ")"
syntax Id ::= "%standard_metadata_t" [token]
syntax Val ::= "@undef"



configuration
<T>
    <programs> @createNodes($PGM:P4Programs, 0)  </programs>
    <topology> .Map </topology>
    <nodes>
        <node multiplicity="*">
            <nodeId> .K </nodeId>
            //<k>  $PGM:P4Program ~> @parseOrder (start) ~> @init ~> @exec  </k>
            <k> .K </k>


            <headers>
                <header multiplicity="*">
                    <name> .K </name>
                    <opts> .K </opts>
                    <fields> .K </fields>
                </header>
            </headers>

            <instances>
                <instance multiplicity="*">
                    <valid> .K </valid>
                    <metadata> .K </metadata>
                    <typeName> .K </typeName>
                    <name> .K </name>
                    <fieldVals> .Map </fieldVals>
                </instance>
            </instances>

            <parserStates>
                <state multiplicity="*">
                    <name> .K </name>
                    <body> .K </body>
                </state>
            </parserStates>


            <actions>
                <action multiplicity="*">
                    <name> .K </name>
                    <params> .K </params>
                    <body> .K </body>
                </action>
            </actions>

            <tables>
                <table multiplicity="*">
                    <name> .K </name>
                    <reads> .K </reads>
                    <acts> .K </acts>
                    <opts> .K </opts>
                    <rules> .List </rules>
                </table>
            </tables>

            <controlFlows>
                <control multiplicity="*">
                    <name> .K </name>
                    <body> .K </body>
                </control>
            </controlFlows>

            <cfset> .Set </cfset> //TODO: temporary fix for K issue #2279

            <frameStack>
                .List
            </frameStack>


            <packet>
                .K
            </packet>


            <packetout>
                .List
            </packetout>


            <parser>
                <graph>
                    <marked> .Set </marked>
                    <dporder> .List </dporder>
                </graph>
                <index> 0 </index>
                <lastExt> .K </lastExt>
            </parser>

            //<input stream="stdin">
            //    .List
            //</input>

            <buffer>
                <bin> .List </bin>
                <bout> .List </bout>
            </buffer>
        </node>
    </nodes>

</T>


syntax KItem ::= "@createNodes" "(" P4Programs "," Int ")"


rule <programs> @createNodes(P:P4Program ---- Ps:P4Programs , C:Int) => @createNodes(Ps:P4Programs , C +Int 1) </programs>
     <nodes>
        (.Bag => <node>
                    <nodeId> C </nodeId>
                    <k>  P ~> @parseOrder (start) ~> @init ~> @exec  </k>
                 ...
                 </node>
        )
     ...
     </nodes>


syntax KItem ::= "@nextPacket"


//-network-
syntax SPort ::= "$node_port" "(" Int "," Int ")"
rule <programs> @createNodes(.P4Programs, _:Int) => . </programs>
     <topology> (.Map => $node_port(0,3) |-> $node_port(1,1)  $node_port(1,3) |-> $node_port(2,1))  </topology>


rule <topology> ... $node_port(SN:Int,SP:Int) |-> $node_port(DN:Int,DP:Int) </topology>
     <node> <nodeId> SN </nodeId> <bout> (ListItem($packet(P:List,SP)) => .List) _:List </bout> ... </node>
     <node> <nodeId> DN </nodeId> <k> @nextPacket ... </k> <bin> .List => ListItem($packet(P,DP)) </bin> ... </node>


//----------------------------init----------------------------------
rule <k> @init => . ... </k>
     <nodeId> 0 </nodeId>
     <headers>
                 (.Bag => <header>
                             <name> %standard_metadata_t </name>
                             <opts> .HeaderOptionals </opts>
                             <fields>
                                String2Id("ingress_port") : #token("32","DecimalValueToken@VALUE-SYNTAX") (.FieldMods);
                                String2Id("egress_spec") : #token("32","DecimalValueToken@VALUE-SYNTAX") (.FieldMods);
                                 .FieldDecs
                             </fields>
                             ...
                         </header>
                 )
                 ...
     </headers>
     <instances>
        (.Bag => <instance>
                    <valid> true </valid>
                    <metadata> true </metadata>
                    <typeName>  %standard_metadata_t </typeName>
                    <name> String2Id("standard_metadata") </name>
                    ...
                 </instance>
        )
        ...
     </instances>
     //TODO: maybe instead of doing above, it would be better to add it as a part of the program
//======Hardcoded input packet and table entries=====
     <tables>
        ...
        <table>
            ...
            <name> port_mapping </name>
            <rules> .List   => (
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 1 , 0 , false )))
                                    , @call(String2Id("set_bd") , $resolved( ListItem(@val(10,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 2 , 0 , false )))
                                    , @call(String2Id("set_bd") , $resolved( ListItem(@val(10,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 3 , 0 , false )))
                                    , @call(String2Id("set_bd") , $resolved( ListItem(@val(20,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 4 , 0 , false )))
                                    , @call(String2Id("set_bd") , $resolved( ListItem(@val(20,0,false)) ) ))
                                 )
                               )
            </rules>
        </table>
        <table>
            ...
            <name> bd </name>
            <rules> .List => (
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 10 , 0 , false )))
                                    , @call(String2Id("set_vrf") , $resolved( ListItem(@val(30,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 20 , 0 , false )))
                                    , @call(String2Id("set_vrf") , $resolved( ListItem(@val(30,0,false)) ) ))
                                 )
                             )
            </rules>
        </table>
        <table>
            ...
            <name> ipv4_fib </name>
            <rules> .List => (
                                 ListItem(
                                    $rule(
                                                                                               //192.168.0.0
                                        $ctr(ListItem(@val ( 30 , 0 , false )) ListItem(@val ( 3232235520 , 0 , false )))
                                    , @call(String2Id("fib_hit_nexthop") , $resolved( ListItem(@val(1,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                                                                               //10.0.0.0
                                        $ctr(ListItem(@val ( 30 , 0 , false )) ListItem(@val ( 167772160 , 0 , false )))
                                    , @call(String2Id("fib_hit_nexthop") , $resolved( ListItem(@val(3,0,false)) ) ))
                                 )
                             )
            </rules>
        </table>
        <table>
            ...
            <name> nexthop </name>
            <rules> .List => (
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 1 , 0 , false )) )
                                    , @call(String2Id("set_egress_details") , $resolved( ListItem(@val(1,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 2 , 0 , false )) )
                                    , @call(String2Id("set_egress_details") , $resolved( ListItem(@val(2,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 3 , 0 , false )) )
                                    , @call(String2Id("set_egress_details") , $resolved( ListItem(@val(3,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 4 , 0 , false )) )
                                    , @call(String2Id("set_egress_details") , $resolved( ListItem(@val(4,0,false)) ) ))
                                 )

                             )
            </rules>
        </table>
        <table>
            ...
            <name> rewrite_mac </name>
            <rules> .List => (
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 1 , 0 , false )) )
                                                                                          //01:01:01:01:01:01                   //00:01:01:01:01:01
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1103823438081,0,false)) ListItem(@val(4311810305,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 2 , 0 , false )) )
                                                                                          //01:02:02:02:02:02                   //00:02:02:02:02:02
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1108135248386,0,false)) ListItem(@val(8623620610,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 3 , 0 , false )) )
                                                                                          //01:03:03:03:03:03                   //00:03:03:03:03:03
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1112447058691,0,false)) ListItem(@val(12935430915,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 4 , 0 , false )) )
                                                                                          //01:04:04:04:04:04                   //00:04:04:04:04:04
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1116758868996,0,false)) ListItem(@val(17247241220,0,false)) ) ))
                                 )
                             )
            </rules>
        </table>
        ...
     </tables>
                    //00:00:00:00:00:01 00:00:00:00:00:00   ....  TTL:64 .... 10.0.0.1 10.0.0.0
                    //0000 0000 0001 0000 0000 0000 0800 4500 0044 ad0b 0000 4011 7272 0a00 0001 0a00 0000
     //<packet> . => "00000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000001000000000000100010100000000000000000100010010101101000010110000000000000000010000000001000101110010011100100000101000000000000000000000000100001010000000000000000000000000" </packet>
     <buffer>
     <bin> .List => ListItem($packet(
                   ListItem(@val(1,48,false)) //dst mac
                   ListItem(@val(0,48,false)) //src mac
                   ListItem(@val(2048,16,false)) //ethertype
                   ListItem(@val(4,4,false)) //ip version
                   ListItem(@val(20,4,false)) //ihl
                   ListItem(@val(0,8,false)) //diffserv
                   ListItem(@val(68,16,false)) //total len
                   ListItem(@val(44299,16,false)) //id
                   ListItem(@val(0,3,false)) //flags
                   ListItem(@val(0,13,false)) //frag offset
                   ListItem(@val(64,8,false)) //ttl
                   ListItem(@val(17,8,false)) //protocol
                   ListItem(@val(7272,16,false)) //checksum
                   ListItem(@val(167772161,32,false)) //src ip
                   ListItem(@val(167772160,32,false)) //dst ip
                   , 1 //port
                   ))
     </bin>
     ...
     </buffer>



rule <k> @init => . ... </k>
     <nodeId> 1 </nodeId>
     <headers>
                 (.Bag => <header>
                             <name> %standard_metadata_t </name>
                             <opts> .HeaderOptionals </opts>
                             <fields>
                                String2Id("ingress_port") : #token("32","DecimalValueToken@VALUE-SYNTAX") (.FieldMods);
                                String2Id("egress_spec") : #token("32","DecimalValueToken@VALUE-SYNTAX") (.FieldMods);
                                 .FieldDecs
                             </fields>
                             ...
                         </header>
                 )
                 ...
     </headers>
     <instances>
        (.Bag => <instance>
                    <valid> true </valid>
                    <metadata> true </metadata>
                    <typeName>  %standard_metadata_t </typeName>
                    <name> String2Id("standard_metadata") </name>
                    ...
                 </instance>
        )
        ...
     </instances>
     //TODO: maybe instead of doing above, it would be better to add it as a part of the program
//======Hardcoded input packet and table entries=====
     <tables>
        ...
        <table>
            ...
            <name> port_mapping </name>
            <rules> .List   => (
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 1 , 0 , false )))
                                    , @call(String2Id("set_bd") , $resolved( ListItem(@val(10,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 2 , 0 , false )))
                                    , @call(String2Id("set_bd") , $resolved( ListItem(@val(10,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 3 , 0 , false )))
                                    , @call(String2Id("set_bd") , $resolved( ListItem(@val(20,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 4 , 0 , false )))
                                    , @call(String2Id("set_bd") , $resolved( ListItem(@val(20,0,false)) ) ))
                                 )
                               )
            </rules>
        </table>
        <table>
            ...
            <name> bd </name>
            <rules> .List => (
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 10 , 0 , false )))
                                    , @call(String2Id("set_vrf") , $resolved( ListItem(@val(30,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 20 , 0 , false )))
                                    , @call(String2Id("set_vrf") , $resolved( ListItem(@val(30,0,false)) ) ))
                                 )
                             )
            </rules>
        </table>
        <table>
            ...
            <name> ipv4_fib </name>
            <rules> .List => (
                                 ListItem(
                                    $rule(
                                                                                               //192.168.0.0
                                        $ctr(ListItem(@val ( 30 , 0 , false )) ListItem(@val ( 3232235520 , 0 , false )))
                                    , @call(String2Id("fib_hit_nexthop") , $resolved( ListItem(@val(1,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                                                                               //10.0.0.0
                                        $ctr(ListItem(@val ( 30 , 0 , false )) ListItem(@val ( 167772160 , 0 , false )))
                                    , @call(String2Id("fib_hit_nexthop") , $resolved( ListItem(@val(3,0,false)) ) ))
                                 )
                             )
            </rules>
        </table>
        <table>
            ...
            <name> nexthop </name>
            <rules> .List => (
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 1 , 0 , false )) )
                                    , @call(String2Id("set_egress_details") , $resolved( ListItem(@val(1,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 2 , 0 , false )) )
                                    , @call(String2Id("set_egress_details") , $resolved( ListItem(@val(2,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 3 , 0 , false )) )
                                    , @call(String2Id("set_egress_details") , $resolved( ListItem(@val(3,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 4 , 0 , false )) )
                                    , @call(String2Id("set_egress_details") , $resolved( ListItem(@val(4,0,false)) ) ))
                                 )

                             )
            </rules>
        </table>
        <table>
            ...
            <name> rewrite_mac </name>
            <rules> .List => (
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 1 , 0 , false )) )
                                                                                          //01:01:01:01:01:01                   //00:01:01:01:01:01
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1103823438081,0,false)) ListItem(@val(4311810305,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 2 , 0 , false )) )
                                                                                          //01:02:02:02:02:02                   //00:02:02:02:02:02
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1108135248386,0,false)) ListItem(@val(8623620610,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 3 , 0 , false )) )
                                                                                          //01:03:03:03:03:03                   //00:03:03:03:03:03
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1112447058691,0,false)) ListItem(@val(12935430915,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 4 , 0 , false )) )
                                                                                          //01:04:04:04:04:04                   //00:04:04:04:04:04
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1116758868996,0,false)) ListItem(@val(17247241220,0,false)) ) ))
                                 )
                             )
            </rules>
        </table>
        ...
     </tables>


rule <k> @init => . ... </k>
     <nodeId> 2 </nodeId>
     <headers>
                 (.Bag => <header>
                             <name> %standard_metadata_t </name>
                             <opts> .HeaderOptionals </opts>
                             <fields>
                                String2Id("ingress_port") : #token("32","DecimalValueToken@VALUE-SYNTAX") (.FieldMods);
                                String2Id("egress_spec") : #token("32","DecimalValueToken@VALUE-SYNTAX") (.FieldMods);
                                 .FieldDecs
                             </fields>
                             ...
                         </header>
                 )
                 ...
     </headers>
     <instances>
        (.Bag => <instance>
                    <valid> true </valid>
                    <metadata> true </metadata>
                    <typeName>  %standard_metadata_t </typeName>
                    <name> String2Id("standard_metadata") </name>
                    ...
                 </instance>
        )
        ...
     </instances>
     //TODO: maybe instead of doing above, it would be better to add it as a part of the program
//======Hardcoded input packet and table entries=====
     <tables>
        ...
        <table>
            ...
            <name> port_mapping </name>
            <rules> .List   => (
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 1 , 0 , false )))
                                    , @call(String2Id("set_bd") , $resolved( ListItem(@val(10,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 2 , 0 , false )))
                                    , @call(String2Id("set_bd") , $resolved( ListItem(@val(10,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 3 , 0 , false )))
                                    , @call(String2Id("set_bd") , $resolved( ListItem(@val(20,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 4 , 0 , false )))
                                    , @call(String2Id("set_bd") , $resolved( ListItem(@val(20,0,false)) ) ))
                                 )
                               )
            </rules>
        </table>
        <table>
            ...
            <name> bd </name>
            <rules> .List => (
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 10 , 0 , false )))
                                    , @call(String2Id("set_vrf") , $resolved( ListItem(@val(30,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 20 , 0 , false )))
                                    , @call(String2Id("set_vrf") , $resolved( ListItem(@val(30,0,false)) ) ))
                                 )
                             )
            </rules>
        </table>
        <table>
            ...
            <name> ipv4_fib </name>
            <rules> .List => (
                                 ListItem(
                                    $rule(
                                                                                               //192.168.0.0
                                        $ctr(ListItem(@val ( 30 , 0 , false )) ListItem(@val ( 3232235520 , 0 , false )))
                                    , @call(String2Id("fib_hit_nexthop") , $resolved( ListItem(@val(1,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                                                                               //10.0.0.0
                                        $ctr(ListItem(@val ( 30 , 0 , false )) ListItem(@val ( 167772160 , 0 , false )))
                                    , @call(String2Id("fib_hit_nexthop") , $resolved( ListItem(@val(3,0,false)) ) ))
                                 )
                             )
            </rules>
        </table>
        <table>
            ...
            <name> nexthop </name>
            <rules> .List => (
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 1 , 0 , false )) )
                                    , @call(String2Id("set_egress_details") , $resolved( ListItem(@val(1,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 2 , 0 , false )) )
                                    , @call(String2Id("set_egress_details") , $resolved( ListItem(@val(2,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 3 , 0 , false )) )
                                    , @call(String2Id("set_egress_details") , $resolved( ListItem(@val(3,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 4 , 0 , false )) )
                                    , @call(String2Id("set_egress_details") , $resolved( ListItem(@val(4,0,false)) ) ))
                                 )

                             )
            </rules>
        </table>
        <table>
            ...
            <name> rewrite_mac </name>
            <rules> .List => (
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 1 , 0 , false )) )
                                                                                          //01:01:01:01:01:01                   //00:01:01:01:01:01
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1103823438081,0,false)) ListItem(@val(4311810305,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 2 , 0 , false )) )
                                                                                          //01:02:02:02:02:02                   //00:02:02:02:02:02
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1108135248386,0,false)) ListItem(@val(8623620610,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 3 , 0 , false )) )
                                                                                          //01:03:03:03:03:03                   //00:03:03:03:03:03
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1112447058691,0,false)) ListItem(@val(12935430915,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 4 , 0 , false )) )
                                                                                          //01:04:04:04:04:04                   //00:04:04:04:04:04
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1116758868996,0,false)) ListItem(@val(17247241220,0,false)) ) ))
                                 )
                             )
            </rules>
        </table>
        ...
     </tables>


syntax Id ::=      "port_mapping" [token]
                 | "bd"           [token]
	             | "ipv4_fib"     [token]
	             | "nexthop"      [token]
	             | "rewrite_mac"  [token]



endmodule
