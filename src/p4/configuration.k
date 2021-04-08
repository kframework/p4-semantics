require "syntax/p4-syntax.k"

module CONFIGURATION
imports P4-COMMON
imports DOMAINS


syntax KItem ::= "@init" | "@exec" | "@fillInitInstances"
syntax KItem ::=  "@parseOrder" "(" KItem ")"
syntax KItem ::= "#parserState" "(" ParserStateName ")"
syntax Id ::= "start" [token]

syntax KItem ::= "empty_cell"


syntax ExecutionMode ::=
                          "PREPROCESSING"
                        | "RUNNING"


configuration
<p4>
    <k>  $PGM:P4Program ~> @parseOrder (#parserState(start)) ~>  @init ~> @fillInitInstances ~> @exec  </k>

    <headers>
        <header multiplicity="*" type="Set">
            <h-name> .K </h-name>
            <h-opts> .Map </h-opts>
            <h-fields> .K </h-fields>
        </header>
    </headers>

    <arrays>
        .Map
    </arrays>

    <fieldLists>
        <fieldList multiplicity="*" type="Set">
            <fl-name> .K </fl-name>
            <fl-fields> .K </fl-fields>
        </fieldList>
    </fieldLists>

    <fieldListCalcs>
        <fieldListCalc multiplicity="*" type="Set">
            <flc-name> .K </flc-name>
            <fLists> .List </fLists>
            <algorithm> .K </algorithm>
            <outWidth> .K </outWidth>
            //Run time APIs allow the selection of one of the input field lists to be active at a time. The first listed name is used as the default.
            <fListIndex> 0 </fListIndex>
        </fieldListCalc>
    </fieldListCalcs>

    <calcFields>
        <calcField multiplicity="*" type="Set">
            <fieldRef> .K </fieldRef>
            <updates> .List </updates>
            <verifies> .List </verifies>
        </calcField>
    </calcFields>

    <instances>
        <instance multiplicity="*" type="Set">
            <valid> .K </valid>
            <metadata> .K </metadata>
            <typeName> .K </typeName>
            <i-name> .K </i-name>
            <fieldVals> .Map </fieldVals>
        </instance>
    </instances>

    <initInstances> .K </initInstances>

    <initArrays> .Map </initArrays> //https://github.com/kframework/k/issues/2352

    <parserStates>
        <state multiplicity="*" type="Set">
            <ps-name> empty_cell    </ps-name>
            <ps-body> empty_cell    </ps-body>
        </state>
    </parserStates>

    <valueSets>
        <valueSet multiplicity="*" type="Set">
            <vs-name> .K </vs-name>
            //a run time API to add and remove values from the set.
            <vals> .Set </vals>
        </valueSet>
    </valueSets>

    <exceptionHandlers>
        <exceptionHandler multiplicity="*" type="Set">
            <eh-name> .K </eh-name>
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
        <stateful multiplicity="*" type="Set">
            <stype> .K </stype>
            <s-name> .K </s-name>
            <s-opts> .Map </s-opts>
            <stfvals> .Map </stfvals>
            //Run time APIs should be provided to indicate the actual width of a given counter.
            <width> .K </width>
        </stateful>
    </statefuls>

    <tableDirects>
        .Map //TableId -> Set  should it be Set or List?
    </tableDirects>

    <actions>
        <action multiplicity="*" type="Set">
            <a-name> .K </a-name>
            <params> .K </params>
            <a-body> .K </a-body>
        </action>
    </actions>

    <actionProfiles>
        <actionProfile multiplicity="*" type="Set">
            <ap-name> .K </ap-name>
            <ap-acts> .K </ap-acts>
            <ap-opts> .Map </ap-opts>
            <entries> .Map </entries>
        </actionProfile>
    </actionProfiles>

    <actionSelectors>
        <actionSelector multiplicity="*" type="Set">
            <as-name> .K </as-name>
            <key> .K </key>
        </actionSelector>
    </actionSelectors>

    <tables>
        <table multiplicity="*" type="Set">
            <t-name> .K </t-name>
            <reads> .K </reads>
            <t-acts> .K </t-acts>
            <t-opts> .K </t-opts>
            <rules> .List </rules>
            <default> .K </default>
        </table>
    </tables>

    <controlFlows>
        <control multiplicity="*" type="Set">
            <c-name> .K </c-name>
            <c-body> .K </c-body>
        </control>
    </controlFlows>

    <cfset> .Set </cfset> //TODO: temporary fix for K issue #2279
    <calcFieldSet> .Set </calcFieldSet> //set or list? depens on which order the calc fields need to be verified

    <ctx>
        <frameStack>
            .List
        </frameStack>
        <crnt> .Map </crnt>
        <packetInit> .Map </packetInit> //intializer carried with packet for resubmit, recurculate, clone
        //<crntTable> .K </crntTable>
        //<crntRule> .K </crntRule>
        //<crntAction> .K </crntAction>
        //<crntHit> .K </crntHit>
    </ctx>


    <packet>
        .K
    </packet>

    <original> //Packet
        .K
    </original>


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
        <in> .List </in>
        <out> .List </out>
    </buffer>

    <exec-mode>
        PREPROCESSING
    </exec-mode>
</p4>

//macros

endmodule
