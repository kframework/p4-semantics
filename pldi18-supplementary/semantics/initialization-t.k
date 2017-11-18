require "configuration.k"



module INITIALIZATION

imports CONFIGURATION

//forward declaration
syntax ActionCall
syntax Criteria



syntax Val ::= "@val" "("Int","Int","Bool")" //int,width,signed
syntax ActionCall ::= "@call" "(" ActionName "," K /* ResolvedArgs */ ")" [strict(2)]
syntax ActionProfileEntryRef ::= "@apref" "(" Int ")"
syntax ActionCallOrActionProfileRef ::= ActionCall | ActionProfileEntryRef


syntax ResolvedArgs ::= "$resolved" "(" List ")"
syntax KResult ::= ResolvedArgs

syntax KResult ::= "$pair" "(" Val "," Val ")"

// --------------------init------------------------------------



syntax Rule ::= "$rule" "(" Int /* Id */ "," Criteria "," ActionCallOrActionProfileRef ")"
syntax Criteria ::= "$ctr" "(" List ")"

syntax PacketData ::= List | String
syntax Packet ::=
        "$packet" "(" PacketData "," Int ")"
      | "$packet" "(" PacketData "," Int "," Map ")"


syntax Id ::=     "%standard_metadata_t" [token]
                | "standard_metadata" [token]
                | "ingress_port" [token]
                | "egress_spec" [token]
                | "instance_type" [token]

syntax Val ::= "@undef"

syntax Val ::= "@new_packet"
rule <k> @init => . ... </k>
     <headers>
                 (.Bag => <header>
                             <name> %standard_metadata_t </name>
                             <opts> .Map </opts>
                             <fields>
                                ingress_port   :    #token("32","DecimalValueToken@VALUE-SYNTAX") (.FieldMods);
                                egress_spec   :    #token("32","DecimalValueToken@VALUE-SYNTAX") (.FieldMods);
                                instance_type   :    #token("32","DecimalValueToken@VALUE-SYNTAX") (.FieldMods);
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
                        (instance_type |-> @new_packet)
                    </fieldVals>
                    ...
                 </instance>
        )
        ...
     </instances>
     //maybe instead of doing above, it would be better to add it as a part of the program (p4-prelude)
//======Hardcoded input packet and table entries=====
#include_data
//===================================================

//note: String2Id("port_mapping") does not match, because String2Id is a function and can not be used in LHS





endmodule
