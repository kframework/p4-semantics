require "configuration.k"



module INITIALIZATION

imports CONFIGURATION

//forward declaration
syntax ActionCall
syntax Criteria



syntax Val ::= "@val" "("Int","Int","Bool")" //int,width,signed
syntax ActionCall ::= "@call" "(" ActionName "," K /* ResolvedArgs */ ")" [strict(2)]

syntax ResolvedArgs ::= "$resolved" "(" List ")"
syntax KResult ::= ResolvedArgs


// --------------------init------------------------------------


//syntax Input ::= "packet" "(" String ")"

//syntax Packet ::= "packet" "(" Int ")"

//syntax Rule ::= "$rule" "(" Criteria  ","  ActionName ")"
//syntax Criteria ::= "$ctr" "(" Matchs ")"
//syntax Matchs ::= List{Match,","} [klable('Matchs)]
//syntax Match ::= FieldOrMaskedRef ":" ConstValue //TODO:complete this

syntax Rule ::= "$rule" "(" Criteria "," ActionCall ")"
syntax Criteria ::= "$ctr" "(" List ")"


syntax Packet ::= "$packet" "(" List "," Int ")"


syntax Id ::= "%standard_metadata_t" [token]

syntax Val ::= "@undef"
rule <k> @init => . ... </k>
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
#include_data
//===================================================

//note: String2Id("port_mapping") does not match, because String2Id is a function and can not be used in LHS





endmodule
