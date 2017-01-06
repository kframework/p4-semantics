require "syntax/p4-syntax.k"



module CONFIGURATION
imports P4-COMMON


syntax KItem ::= "@exec"

configuration
<T>
    <k>  $PGM:P4Program ~> @exec </k>


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
            //<arraysize> .K </arraysize>
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


    //<input stream="stdin">
    //    .List
    //</input>

    <packet>
        .K
    </packet>


</T>


//macros




// putting decralarions into configuration cells

syntax KItem ::=
          "@processDec" "(" K ")"

rule <k> (Dec:P4Declaration Rest:P4Declarations) => @processDec(Dec) ~> Rest ... </k>

rule <k> (.P4Declarations => .) ... </k>

// @processDec


// header dec
//
rule <k> @processDec(header_type Name:HeaderTypeName { fields { Fields:FieldDecs } Opt:HeaderOptionals }) => . ... </k>
    <headers>  (.Bag =>
        <header>  <name> Name </name> <opts> Opt </opts> <fields> Fields </fields>   </header>)
    ... </headers>


rule N:FieldName : W:BitWidth ; => N : W ( .FieldMods ) ; [macro]


// header instance

rule metadata H:HeaderTypeName  I:InstanceName ; => metadata H I { .FieldValueAssignments }  [macro]

rule <k> @processDec(metadata Type:HeaderTypeName Name:InstanceName { Asgn:FieldValueAssignments } ) => . ... </k>
    <instances>  (.Bag =>
        <instance>
             <valid> true </valid>
                <metadata> true </metadata> <typeName> Type </typeName> <name> Name </name> ...
        </instance>
    ) ... </instances>
    <headers>  <header> ... <name> Type </name> ... </header> ... </headers>


rule <k> @processDec(header Type:HeaderTypeName Name:InstanceName ; ) => . ... </k>
    <instances> (.Bag =>
        <instance>
             <valid> false </valid> <metadata> false </metadata> <typeName> Type </typeName> <name> Name </name>  <fieldVals> .Map </fieldVals>
        </instance>
    ) ... </instances>
//rule <k> @processDec(header Type:HeaderTypeName Name:InstanceName [ Size:ConstValue ] ; ) => . ... </k>
//    <instances> ... (.Bag =>
//        <instance>
//            ... <valid> false </valid> <metadata> false </metadata> <typeName> Type </typeName> <name> Name </name> <arraysize> Size </arraysize>   ...
//        </instance>
//    ) ... </instances>
//TODO: array is not supported yet


syntax KItem ::= "@initFields" "(" FieldValueAssignments "," Set "," Map  ")" [function]
//rule @initFields(.FieldValueAssignments, ,Acc)



//parser

rule <k> @processDec(parser Name:ParserStateName { Body:ParserFunctionBody }) => . ... </k>
    <parserStates> (.Bag =>
          <state>
            <name> Name </name> <body> Body </body>
          </state>
    ) ... </parserStates>


//action

rule <k> @processDec(action Name:ActionName ( Params:ParamList ) { Body:ActionStatements }  ) => . ... </k>
    <actions> (.Bag =>
          <action>
            <name> Name </name> <params> Params </params> <body> Body </body>
          </action>
    ) ... </actions>


//table

rule table N:TableName { A:TableActions O:TableOptionals } => table N { reads { .FieldMatchs } A O } [macro]

rule <k> @processDec(table Name:TableName { Read:Reads Act:TableActions Opt:TableOptionals } ) => . ... </k>
         <tables>... (.Bag =>
               <table>
                 <name> Id2String(Name:>Id) </name> <reads> Read </reads> <acts> Act </acts> <opts> Opt </opts> <rules> .List </rules>
               </table>
         ) ... </tables>


// control

rule <k> @processDec(control Name:ControlFnName { Body:ControlStatements } ) => . ... </k>
         <controlFlows> (.Bag =>
               <control>
                    <name> Name </name> <body> Body </body>
               </control>
         ) ... </controlFlows>


// --------------------

syntax KItem ::= "@init" | "@parse" | "@ingress" | "@egress"

rule @exec => @init ~> @parse ~> @ingress ~> @egress


//syntax Input ::= "packet" "(" String ")"

//syntax Packet ::= "packet" "(" Int ")"

syntax Rule ::= "$rule" "(" Criteria   /* ActionName */ ")"
syntax Criteria ::= "$ctr" "(" Matchs ")"
syntax Matchs ::= List{Match,","} [klable('Matchs)]
syntax Match ::= FieldOrMaskedRef ":" ConstValue //TODO:complete this

//temprory
rule <k> @init => . ... </k>
     <packet> . => "00100001010101010" </packet>
     <tables>
        ...
        <table>
            ...
            <name> "egress_meter" </name>
            <rules> .List => ListItem($rule($ctr(String2Id("ethernet").String2Id("dstAddr") : #token("10","DecimalValueToken@VALUE-SYNTAX"))))</rules>
        </table>
        ...
     </tables>



//parsing
syntax Id ::= "start" [token]
rule <k> @parse => Body  ... </k>
     <parserStates> <state>  <name> start </name> <body> Body </body> ... </state> ...</parserStates>

rule ESs:ExtractOrSetStatements R:ReturnStatement => ESs ~> R           [structural]
rule ES:ExtractOrSetStatement ESs:ExtractOrSetStatements => ES ~> ESs   [structural]

rule .ExtractOrSetStatements => .

rule <k> return State:ParserStateName ; => Body ... </k>
     <parserStates> <state>  <name> State </name> <body> Body </body> ... </state> ...</parserStates>

//rule extract()


endmodule