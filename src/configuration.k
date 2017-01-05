require "syntax/p4-syntax.k"



module CONFIGURATION
imports P4-COMMON


syntax KItem ::= "@exec"

configuration
<T>
    <k>  $PGM:P4Program ~> @exec </k>


    <headers>
        <header multiplicity="*">
            .K
        </header>
    </headers>

    <instances>
        <instance multiplicity="*">
            <metadata> .K </metadata>
            <typeName> .K </typeName>
            <name> .K </name>
            <fieldVals> .Map </fieldVals>
            <arraysize> .K </arraysize>
            <init> .K </init>
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


// putting decralarions into configuration cells



syntax KItem ::=
          "@processDec" "(" K ")"

rule <k> (Dec:P4Declaration Rest:P4Declarations) => @processDec(Dec) ~> Rest ... </k>

rule <k> (.P4Declarations => .) ... </k>

// @processDec

rule <k> @processDec(Header:HeaderTypeDeclaration) => . ... </k>
    <headers> ... (.Bag => <header> Header </header>) ... </headers>


// header

rule <k> @processDec(metadata Type:HeaderTypeName Name:InstanceName ;) => . ... </k>
    <instances> ... (.Bag =>
        <instance>
            ... <metadata> true </metadata> <typeName> Type </typeName> <name> Name </name>   ...
        </instance>
    ) ... </instances>
rule <k> @processDec(metadata Type:HeaderTypeName Name:InstanceName { Asgn:FieldValueAssignments } ) => . ... </k>
    <instances> ... (.Bag =>
        <instance>
            ... <metadata> true </metadata> <typeName> Type </typeName> <name> Name </name> <init> Asgn </init>  ...
        </instance>
    ) ... </instances>
rule <k> @processDec(header Type:HeaderTypeName Name:InstanceName ; ) => . ... </k>
    <instances> ... (.Bag =>
        <instance>
            ... <metadata> false </metadata> <typeName> Type </typeName> <name> Name </name>  ...
        </instance>
    ) ... </instances>
rule <k> @processDec(header Type:HeaderTypeName Name:InstanceName [ Size:ConstValue ] ; ) => . ... </k>
    <instances> ... (.Bag =>
        <instance>
            ... <metadata> false </metadata> <typeName> Type </typeName> <name> Name </name> <arraysize> Size </arraysize>   ...
        </instance>
    ) ... </instances>


//parser

rule <k> @processDec(parser Name:ParserStateName { Body:ParserFunctionBody }) => . ... </k>
    <parserStates>... (.Bag =>
          <state>
            <name> Name </name> <body> Body </body>
          </state>
    ) ... </parserStates>


//action

rule <k> @processDec(action Name:ActionName ( Params:ParamList ) { Body:ActionStatements }  ) => . ... </k>
    <actions>... (.Bag =>
          <action>
            <name> Name </name> <params> Params </params> <body> Body </body>
          </action>
    ) ... </actions>


//table

rule <k> @processDec(table Name:TableName { Read:Reads Act:TableActions Opt:TableOptionals } ) => . ... </k>
         <tables>... (.Bag =>
               <table>
                 <name> Id2String(Name:>Id) </name> <reads> Read </reads> <acts> Act </acts> <opts> Opt </opts> ...
               </table>
         ) ... </tables>

rule <k> @processDec(table Name:TableName {Act:TableActions Opt:TableOptionals } ) => . ... </k>
         <tables>... (.Bag =>
               <table>
                 ...<name> Id2String(Name:>Id) </name> <acts> Act </acts> <opts> Opt </opts>...
               </table>
         ) ... </tables>

// control

rule <k> @processDec(control Name:ControlFnName { Body:ControlStatements } ) => . ... </k>
         <controlFlows>... (.Bag =>
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



//syntax KItem ::= "start"
rule <k> @parse => .  ... </k>
     <parserStates>... <state> ... <name> Name:Id </name> ... </state> ...</parserStates>








endmodule