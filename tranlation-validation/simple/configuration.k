require "../../src/syntax/p4-syntax.k"
require "common.k"

module CONFIGURATION
imports P4-COMMON
imports COMMON
syntax ActionCall ::= "@call" "(" Id "," K /* ResolvedArgs */ ")" [strict(2)]

syntax KItem ::= "@init" | "@exec" | "@fillInitInstances"
syntax KItem ::=  "@parseOrder" "(" K ")"
syntax Id ::= "start" [token]







configuration
<L1>
    <k>  $PGM:P4Program ~> @parseOrder (start) ~>  @init ~> @fillInitInstances ~> @exec  </k>

    <headers>
        <header multiplicity="*">
            <name> .K </name>
            <opts> .Map </opts>
            <fields> .K </fields>
        </header>
    </headers>

    <arrays>
        .Map
    </arrays>

    <fieldLists>
        <fieldList multiplicity="*">
            <name> .K </name>
            <fields> .K </fields>
        </fieldList>
    </fieldLists>

    <fieldListCalcs>
        <fieldListCalc multiplicity="*">
            <name> .K </name>
            <fLists> .List </fLists>
            <algorithm> .K </algorithm>
            <outWidth> .K </outWidth>
            //Run time APIs allow the selection of one of the input field lists to be active at a time. The first listed name is used as the default.
            <fListIndex> 0 </fListIndex>
        </fieldListCalc>
    </fieldListCalcs>

    <calcFields>
        <calcField multiplicity="*">
            <fieldRef> .K </fieldRef>
            <updates> .List </updates>
            <verifies> .List </verifies>
        </calcField>
    </calcFields>

    <instances>
        <instance multiplicity="*">
            <valid> .K </valid>
            <metadata> .K </metadata>
            <typeName> .K </typeName>
            <name> .K </name>
            <fieldVals> .Map </fieldVals>
        </instance>
    </instances>

    <initInstances> .K </initInstances>

    <initArrays> .Map </initArrays> //https://github.com/kframework/k/issues/2352

    <parserStates>
        <state multiplicity="*">
            <name> .K </name>
            <body> .K </body>
        </state>
    </parserStates>

    <valueSets>
        <valueSet multiplicity="*">
            <name> .K </name>
            //a run time API to add and remove values from the set.
            <vals> .Set </vals>
        </valueSet>
    </valueSets>

    <exceptionHandlers>
        <exceptionHandler multiplicity="*">
            <name> .K </name>
            <pebody>
                <setsts> .K </setsts>
                <return> .K </return>
            </pebody>
        </exceptionHandler>
    </exceptionHandlers>

    <handledExceptions>
        .Set
    </handledExceptions>

    <statefuls>
        <stateful multiplicity="*">
            <stype> .K </stype>
            <name> .K </name>
            <opts> .Map </opts>
            <vals> .Map </vals>
            //Run time APIs should be provided to indicate the actual width of a given counter.
            <width> .K </width>
        </stateful>
    </statefuls>

    <tableDirects>
        .Map //TableId -> Set  should it be Set or List?
    </tableDirects>

    <actions>
        <action multiplicity="*">
            <name> .K </name>
            <params> .K </params>
            <body> .K </body>
        </action>
    </actions>

    <actionProfiles>
        <actionProfile multiplicity="*">
            <name> .K </name>
            <acts> .K </acts>
            <opts> .Map </opts>
            <entries> .Map </entries>
        </actionProfile>
    </actionProfiles>

    <actionSelectors>
        <actionSelector multiplicity="*">
            <name> .K </name>
            <key> .K </key>
        </actionSelector>
    </actionSelectors>

    <tables>
        <table multiplicity="*">
            <name> .K </name>
            <reads> .K </reads>
            <acts> .K </acts>
            <opts> .K </opts>
            <rules> .List </rules>
            <default> .K </default>
        </table>
    </tables>

    <controlFlows>
        <control multiplicity="*">
            <name> .K </name>
            <body> .K </body>
        </control>
    </controlFlows>

    <cfset> .Set </cfset> //TODO: temporary fix for K issue #2279
    <calcFieldSet> .Set </calcFieldSet> //set or list? depens on which order the calc fields need to be verified

    <ctx>
        <frameStack>
            .List
        </frameStack>
        <crnt> .Map </crnt>
        //<crntTable> .K </crntTable>
        //<crntRule> .K </crntRule>
        //<crntAction> .K </crntAction>
        //<crntHit> .K </crntHit>
    </ctx>


    <packet>
        .K
    </packet>


    <packetout>
        .List
    </packetout>


    <parser>
        <graph>
            <onpath> .Set </onpath>
            <marked>
                <mstates> .Set </mstates>
                <mheaders> .Set </mheaders>
            </marked>
            <dporder> .List </dporder>
        </graph>
        <pctx>
            <index> 0 </index>
            <lastExt> .K </lastExt>
            <varWidth> .K </varWidth>
            <packetSize> .K </packetSize>
        </pctx>
    </parser>

    //<input stream="stdin">
    //    .List
    //</input>

    <buffer>
        <in> $nilPacketList </in>
        <out> $nilPacketList </out>
    </buffer>

</L1>


//macros

endmodule
