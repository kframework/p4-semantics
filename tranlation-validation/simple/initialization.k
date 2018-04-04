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
     <insts> (.List => ListItem(standard_metadata)) _:List </insts>
     //maybe instead of doing above, it would be better to add it as a part of the program (p4-prelude)
//======Hardcoded input packet and table entries=====
<tables> ... <table> ...
    <name> t </name>
    //<rules> _ => $consEntryList($rule(1,$ctr(@cons(@val(0,8,false),  @nil)), @rcall(b, $rv(@nil))), $nilEntryList) </rules>
    <rules> _ => $consEntryList($rule(1,$ctr(@cons(@val(1,8,false),  @nil)), @rcall(b, $rv(@nil))), $nilEntryList) </rules>
    <default> $nothing => @rcall(b, $rv(@nil)) </default>
</table> </tables>
<in> _ => $consPacketList($packet(@cons(@val(0,8,false) , @cons (@val(0,8,false) , @nil)), 30), $nilPacketList) </in>

//===================================================

syntax Id ::= "t" [token]
//note: String2Id("port_mapping") does not match, because String2Id is a function and can not be used in LHS





endmodule
