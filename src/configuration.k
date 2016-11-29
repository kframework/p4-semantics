require "syntax/p4-syntax.k"



module CONFIGURATION
imports P4-COMMON


syntax KItem ::= "@exec"

configuration
<T>
    <k>  $PGM:P4Program ~> @exec </k>

    <tables>
        <table multiplicity="*">
            .K
        </table>
    </tables>

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


    <input>
        .K
    </input>

</T>


// putting decralarions into configuration cells



rule <k> (H:HeaderTypeDeclaration Rest:P4Declarations) => Rest ... </k>
     <headers> ... (.Bag => <header> H </header>) ... </headers>


syntax KItem ::=
          "@processInstanceDec" "(" K ")"
        | "@processParserDec" "(" K ")"
        | "@processActionDec" "(" K ")"

rule <k> (I:InstanceDeclaration Rest:P4Declarations) => @processInstanceDec(I) ~> Rest ... </k>
rule <k> (P:ParserFunctionDeclaration Rest:P4Declarations) => @processParserDec(P) ~> Rest ... </k>
rule <k> (A:ActionFunctionDeclaration Rest:P4Declarations) => @processActionDec(A) ~> Rest ... </k>

rule <k> (.P4Declarations => .) ... </k>


//  @processInstanceDec

rule <k> @processInstanceDec(metadata Type:HeaderTypeName Name:InstanceName ;) => . ... </k>
    <instances> ... (.Bag =>
        <instance>
            ... <metadata> true </metadata> <typeName> Type </typeName> <name> Name </name>   ...
        </instance>
    ) ... </instances>
rule <k> @processInstanceDec(metadata Type:HeaderTypeName Name:InstanceName { Asgn:FieldValueAssignments } ) => . ... </k>
    <instances> ... (.Bag =>
        <instance>
            ... <metadata> true </metadata> <typeName> Type </typeName> <name> Name </name> <init> Asgn </init>  ...
        </instance>
    ) ... </instances>
rule <k> @processInstanceDec(header Type:HeaderTypeName Name:InstanceName ; ) => . ... </k>
    <instances> ... (.Bag =>
        <instance>
            ... <metadata> false </metadata> <typeName> Type </typeName> <name> Name </name>  ...
        </instance>
    ) ... </instances>
rule <k> @processInstanceDec(header Type:HeaderTypeName Name:InstanceName [ Size:ConstValue ] ; ) => . ... </k>
    <instances> ... (.Bag =>
        <instance>
            ... <metadata> false </metadata> <typeName> Type </typeName> <name> Name </name> <arraysize> Size </arraysize>   ...
        </instance>
    ) ... </instances>



// @processParserDec

rule <k> @processParserDec(parser Name:ParserStateName { Body:ParserFunctionBody }) => . ... </k>
    <parserStates>... (.Bag =>
          <state>
            <name> Name </name> <body> Body </body>
          </state>
    ) ... </parserStates>


// @processActionDec


rule <k> @processActionDec(action Name:ActionName ( Params:ParamList ) { Body:ActionStatements } ) => . ... </k>
    <actions>... (.Bag =>
          <action>
            <name> Name </name> <params> Params </params> <body> Body </body>
          </action>
    ) ... </actions>

endmodule