require "configuration.k"



module INITIALIZATION

imports CONFIGURATION

//forward declaration
syntax ActionCall
syntax Criteria






syntax Id ::=     "%standard_metadata_t" [token]
                | "standard_metadata" [token]
                | "ingress_port" [token]
                | "egress_spec" [token]

syntax Val ::= "@undef"
rule <k> @init => . ... </k>
     <headers>
                 (.Bag => <header>
                             <name> %standard_metadata_t </name>
                             <opts> .Map </opts>
                             <fields>
                                ingress_port   :    #token("32","DecimalValueToken@VALUE-SYNTAX") (.FieldMods);
                                egress_spec   :    #token("32","DecimalValueToken@VALUE-SYNTAX") (.FieldMods);
                                //TODO
/*                                String2Id("egress_port") : #token("32","DecimalValueToken@VALUE-SYNTAX") (.FieldMods);
                                String2Id("packet_length") : #token("32","DecimalValueToken@VALUE-SYNTAX") (.FieldMods);
                                String2Id("instance_type") : #token("32","DecimalValueToken@VALUE-SYNTAX") (.FieldMods);*/
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
                    <name> standard_metadata </name>
                    <fieldVals>
                        (ingress_port |-> @undef)
                        (egress_spec |-> @undef)
                    </fieldVals>
                    ...
                 </instance>
        )
        ...
     </instances>
     //maybe instead of doing above, it would be better to add it as a part of the program (p4-prelude)
//======Hardcoded input packet and table entries=====
     <tables>
        ...
        <table>
            ...
            <name> read_reg_table </name>
            <rules> .List   => (
                                 ListItem(
                                    $rule(0,
                                        $ctr(ListItem(@val ( 1 , 0 , false )))
                                    , @call(String2Id("read_reg") , $resolved( .List ) ) )
                                 )
                               )
            </rules>
        </table>
        <table>
            ...
            <name> balance_table </name>
            <rules> .List   => (
                                 ListItem(
                                    $rule(0,
                                        $ctr(ListItem(@val ( 0 , 0 , false )))
                                    , @call(String2Id("balance") , $resolved( ListItem(@val(0,0,false)) ListItem(@val(1,0,false)) ) ) )
                                 )
                                 ListItem(
                                     $rule(1,
                                         $ctr(ListItem(@val ( 1 , 0 , false )))
                                     , @call(String2Id("balance") , $resolved( ListItem(@val(1,0,false)) ListItem(@val(0,0,false)) ) ) )
                                  )
                               )
            </rules>
        </table>

     </tables>
     //<in> _:PacketList => $consPacketList($packet(.List, 0) , $nilPacketList) </in>


syntax Id ::=      "read_reg_table" [token] | "balance_table" [token]
//===================================================

//note: String2Id("port_mapping") does not match, because String2Id is a function and can not be used in LHS





endmodule
