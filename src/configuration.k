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

    <parser>
        .K
    </parser>

    <input>
        .K
    </input>

</T>


// putting decralarions into configuration cells



rule <k> (H:HeaderTypeDeclaration Rest:P4Declarations) => Rest ... </k>
     <headers> ... (.Bag => <header> H </header>) ... </headers>


syntax KItem ::= "@processInstanceDec" "(" K ")"
rule <k> (I:InstanceDeclaration Rest:P4Declarations) => @processInstanceDec(I) ~> Rest ... </k>

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






endmodule