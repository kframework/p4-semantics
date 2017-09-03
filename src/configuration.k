require "syntax/p4-syntax.k"

module CONFIGURATION
imports P4-COMMON

syntax KItem ::= "@init" | "@exec"
syntax KItem ::=  "@parseOrder" "(" K ")"
syntax Id ::= "start" [token]


configuration
<T>
    <k>  $PGM:P4Program ~> @parseOrder (start) ~> @init ~> @exec  </k>


    <headers>
        <header multiplicity="*">
            <name> .K </name>
            <opts> .Map </opts>
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
        <varWidth> .K </varWidth>
    </parser>

    //<input stream="stdin">
    //    .List
    //</input>

    <buffer>
        <in> .List </in>
        <out> .List </out>
    </buffer>



</T>


//macros

endmodule
