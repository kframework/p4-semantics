require "configuration.k"
require "initialization.k"


module P4-SEMANTICS
imports P4-COMMON
imports CONFIGURATION
imports INITIALIZATION

//macros
syntax Val ::= "%DROP_PORT" // [function]
//rule %DROP_PORT => @val(0,32,false) [macro]
syntax Val ::= "%SPECIAL_OPERATION_PORT" [klabel(SPECIAL_OPERATION_PORT), symbol]

syntax Int ::= "#csum16" "(" Int "," Int "," Int ")"       [hook(CSUM.csum16),   function]


//---------------- putting decralarions into configuration cells--------------------------------

syntax KItem ::=
          "@processDec" "(" K ")"

rule <k> (Dec:P4Declaration Rest:P4Declarations) => @processDec(Dec) ~> Rest ... </k>

rule <k> (.P4Declarations => .) ... </k>

// @processDec


// header dec
rule <k> @processDec(header_type Name:HeaderTypeName { fields { Fields:FieldDecs } Opts:HeaderOptionals }) => . ... </k>
    <headers>  (.Bag =>
        <header>  <h-name> Name </h-name> <h-opts> @processHeaderOpts(Opts, .Map) @sumofFixedWidthBits(Fields, 0) </h-opts> <h-fields> Fields </h-fields>  </header>)
    ... </headers>

rule N:FieldName : W:BitWidth ; => N : W ( .FieldMods ) ; [macro]

syntax Map ::= "@processHeaderOpts" "(" HeaderOptionals "," Map ")" [function]
rule @processHeaderOpts(.HeaderOptionals, M:Map) => M
rule @processHeaderOpts(length : LE:LengthExp ; Rest:HeaderOptionals, M:Map) => @processHeaderOpts(Rest, ("length" |-> LE) M)
rule @processHeaderOpts(max_length : MW:UnsignedValue ; Rest:HeaderOptionals, M:Map) => @processHeaderOpts(Rest, ("max_length" |-> USgnVal2Int(MW)) M) //TODO(minor): MW should be ConstValue

syntax Map ::= "@sumofFixedWidthBits" "(" FieldDecs "," Int ")" [function]
rule @sumofFixedWidthBits(.FieldDecs, I:Int) => "$fixed_width" |-> I
rule @sumofFixedWidthBits(_:FieldName : W:UnsignedValue ( _:FieldMods); Rest:FieldDecs, I:Int) => @sumofFixedWidthBits(Rest, I +Int USgnVal2Int(W)) //TODO(minor): W should be ConstValue
rule @sumofFixedWidthBits(_:FieldName : * ( _:FieldMods); Rest:FieldDecs, I:Int) => @sumofFixedWidthBits(Rest, I)

// field_list dec
rule <k> @processDec(field_list Name:FieldListName { FL:FieldListEntryItems }) => . ... </k>
     <fieldLists>
         (.Bag => <fieldList> <fl-name> Name </fl-name> <fl-fields> FL </fl-fields> ... </fieldList>
         ) ...
     </fieldLists>


// field_list_calculation dec
rule <k> @processDec(field_list_calculation Name:FieldListCalculationName { input { FLs:FieldListNameItems }  algorithm : A:StreamFunctionAlgorithmName ; output_width : W:UnsignedValue ; } ) => . ... </k> //TODO(minor): W should be ConstValue
     <fieldListCalcs>
        (.Bag => <fieldListCalc> <flc-name> Name </flc-name> <fLists> @FLAsList(FLs, .List) </fLists> <algorithm> A </algorithm> <outWidth> USgnVal2Int(W) </outWidth> ... </fieldListCalc>
        ) ...
     </fieldListCalcs>

syntax List ::= "@FLAsList" "(" FieldListNameItems "," List")" [function]
rule @FLAsList(N:FieldListName; Rest:FieldListNameItems, L:List ) => @FLAsList(Rest, ListItem(N) L)
rule @FLAsList(.FieldListNameItems, L:List ) => L


// calculated_field dec
rule <k> @processDec(calculated_field F:FieldRef { UV:UpdateVerifySpecs } ) => . ... </k>
     <calcFields>
        (.Bag => <calcField> <fieldRef> F </fieldRef> <updates> @getUpdateOrVerify(update, UV, .List) </updates> <verifies> @getUpdateOrVerify(verify, UV, .List) </verifies>  ... </calcField>
        ) ...
     </calcFields>
     <calcFieldSet> (.Set => SetItem(F)) _:Set </calcFieldSet>


syntax CalcBoolCond ::= Bool
rule UV:UpdateOrVerify N:FieldListCalculationName ; => UV N if ( true ); [macro]

syntax List ::= "@getUpdateOrVerify" "(" UpdateOrVerify "," UpdateVerifySpecs "," List ")" [function]
rule @getUpdateOrVerify(T:UpdateOrVerify, UV:UpdateOrVerify N:FieldListCalculationName C:IfCond ;  Rest:UpdateVerifySpecs, L:List) =>
    #if (T ==K UV) #then @getUpdateOrVerify(T, Rest, ListItem(UV N C;) L) #else @getUpdateOrVerify(T, Rest, L) #fi
rule @getUpdateOrVerify(_, .UpdateVerifySpecs , L:List) => L


// header instance

rule metadata H:HeaderTypeName  I:InstanceName ; => metadata H I { .FieldValueAssignments }  [macro]


rule <k> @processDec(metadata Type:HeaderTypeName Name:InstanceName { Asgn:FieldValueAssignments } ) => @initInstance(Name,@getAssignmentsAsMap(Asgn, .Map)) ... </k>
    <instances>  (.Bag =>
        <instance>
             <valid> true </valid>
             <metadata> true </metadata>
             <typeName> Type </typeName>
             <i-name> Name </i-name>
             <fieldVals> .Map </fieldVals>  ...
        </instance>
    ) ... </instances>
    <headers>  <header>  <h-name> Type </h-name> ... </header> ... </headers>


rule <k> @processDec(header Type:HeaderTypeName Name:InstanceName ; ) => . ... </k>
    <instances> (.Bag =>
        <instance>
             <valid> false </valid> <metadata> false </metadata> <typeName> Type </typeName> <i-name> Name </i-name>  ...
        </instance>
    ) ... </instances>
rule <k> @processDec(header Type:HeaderTypeName Name:InstanceName [ Size:UnsignedValue ] ; ) => @createArrayElement(Type, Name, USgnVal2Int(Size)) ... </k> //TODO (minor) : Size should be ConstValue
     <arrays> (.Map => Name |-> $array(USgnVal2Int(Size), 0, -1)) _:Map </arrays>

syntax KItem ::= "@createArrayElement" "(" HeaderTypeName "," InstanceName "," Int ")"
rule @createArrayElement(_,_,0) => .K
rule <k> @createArrayElement(T:HeaderTypeName,N:InstanceName,(I:Int => (I -Int 1))) ... </k>
     <instances> (.Bag =>
             <instance>
                  <valid> false </valid> <metadata> false </metadata> <typeName> T </typeName> <i-name> $element(N,I -Int 1) </i-name>  ...
             </instance>
         ) ... </instances>
     when I >Int 0

syntax Set ::= "@getFieldsSet" "(" FieldDecs "," Set ")" [function]
rule @getFieldsSet(N:FieldName : _:BitWidth ( _:FieldMods ) ; Rest:FieldDecs, Acc:Set) => @getFieldsSet(Rest, SetItem(N) Acc)
rule @getFieldsSet(.FieldDecs, Acc:Set) => Acc
//TODO: check a field is not decrlared twice

syntax Map ::= "@getAssignmentsAsMap" "(" FieldValueAssignments "," Map ")" [function]
rule @getAssignmentsAsMap(.FieldValueAssignments, M:Map) => M
rule @getAssignmentsAsMap(F:FieldName : V:FieldValue ; R:FieldValueAssignments, M:Map) => @getAssignmentsAsMap(R, (F |-> V) M)

syntax KItem ::=   "@initInstance" "(" InstanceName ")"
                 | "@initInstance" "(" InstanceName "," Map ")" //Map from field to init value

rule @initInstance(I:InstanceName) => @initInstance(I, .Map)
rule <k> @initInstance(I:InstanceName, M:Map) => @initFields(I, M, @getFieldsSet(Fs, .Set)) ... </k>
     <instances> <instance> <i-name> I </i-name> <typeName> T:HeaderTypeName </typeName> <valid> _ => true </valid> ... </instance> ... </instances>
     <headers> <header> <h-name> T </h-name> <h-fields> Fs:FieldDecs </h-fields> ... </header> ... </headers>


syntax KItem ::= "@initFields" "(" InstanceName "," Map "," Set ")"
rule @initFields(_, .Map, .Set) => .
rule (.K => @initFieldAdjusted(I,F,@val(0,0,false))) ~> @initFields(I, .Map, (SetItem(F:FieldName) => .Set) _:Set)
rule (.K => @initFieldAdjusted(I,F,V)) ~> @initFields(I, ((F:FieldName |-> V:KItem) => .Map) _:Map, (SetItem(F:FieldName) => .Set) _:Set)

syntax KItem ::= "@initFieldAdjusted" "(" InstanceName "," FieldName "," KItem /* Val */ ")" [strict(3)]
rule <k> @initFieldAdjusted(N,F,V:Val) => @initField(N,F,@adjustVal(@getAttr(F,Fs),V)) ...</k>
        <instances>
            <instance> <i-name> N </i-name>  <typeName> H:HeaderTypeName </typeName>  ... </instance>
            ...
        </instances>
        <headers>
            <header> <h-name> H </h-name> <h-fields> Fs:FieldDecs </h-fields> ... </header>
            ...
        </headers>

syntax KItem ::= "@initField" "(" InstanceName "," FieldName "," KItem /* Val */ ")" [strict(3)]
rule <k> @initField(N,F,V:Val) => . ...</k>
        <instances>
            <instance> <i-name> N </i-name>  <fieldVals> (.Map => F |-> V) _:Map </fieldVals>  ... </instance>
            ...
        </instances>


//parser

rule <k> @processDec(parser Name:ParserStateName { Body:ParserFunctionBody }) => . ... </k>
    <parserStates> (.Bag =>
          <state>
            <ps-name> Name </ps-name> <ps-body> Body </ps-body>
          </state>
    ) ... </parserStates>

// value set
rule <k> @processDec(parser_value_set Name:ValueSetName ;) => . ... </k>
     <valueSets>
        (.Bag => <valueSet> <vs-name> Name </vs-name> ... </valueSet>)
     ...
     </valueSets>

// exception
rule <k> @processDec(parser_exception Name:ParserExceptionName { S:SetStatements R:ReturnOrDrop ;}) => . ... </k>
     <exceptionHandlers>
        (.Bag => <exceptionHandler> <eh-name> Name </eh-name> <pebody> <setsts> S </setsts> <return> R </return> ... </pebody> ... </exceptionHandler>)
     ...
     </exceptionHandlers>
     <handledExceptions>
        (.Set => SetItem(Name))_:Set
     </handledExceptions>


// stateful
   syntax StatefulType ::= "$counter" | "$meter" | "$register"
   syntax BindingType ::= "$direct" | "$static" | "$static_global"

rule <k> @processDec(counter Name:Id { type : T:CounterType ; SOpt:StatefulOptionals COpt:CounterOptionals }) => @addTableDirect(Name) ... </k>
     <statefuls>
        (.Bag =>
            <stateful>
                <stype> $counter </stype>
                <s-name> Name </s-name>
                <s-opts> ("$counter_type" |-> T) @processStatefulOpts(SOpt, ("$binding" |-> $static_global)) @processCounterOpts(COpt, ("$signed" |-> false) ("$saturating" |-> false)) </s-opts>
                <width> 0 </width> // = inf
                <stfvals> .Map </stfvals> // https://github.com/kframework/k/issues/2351
                ...
            </stateful>
        ) ...
     </statefuls>

rule <k> @processDec(meter Name:Id { type : T:MeterType ; MOpt:MeterOptionals SOpt:StatefulOptionals }) =>  @addTableDirect(Name) ... </k>
     <statefuls>
        (.Bag =>
            <stateful>
                <stype> $meter </stype>
                <s-name> Name </s-name>
                <s-opts> ("$meter_type" |-> T) @processStatefulOpts(SOpt, ("$binding" |-> $static_global)) @processMeterOpts(MOpt, ("$signed" |-> false) ("$saturating" |-> false)) </s-opts>
                <width> 2 </width>
                <stfvals> .Map </stfvals>
                ...
            </stateful>
        ) ...
     </statefuls>

rule <k> @processDec(register Name:Id { width : W:UnsignedValue ; SOpt:StatefulOptionals ROpt:RegisterOptionals }) => . ... </k>     //TODO(minor): W should be ConstValue
     <statefuls>
        (.Bag =>
            <stateful>
                <stype> $register </stype>
                <s-name> Name </s-name>
                <s-opts> @processStatefulOpts(SOpt, ("$binding" |-> $static_global)) @processRegisterOpts(ROpt, ("$signed" |-> false) ("$saturating" |-> false)) </s-opts>
                <width> USgnVal2Int(W) </width>
                <stfvals> .Map </stfvals>
                ...
            </stateful>
        ) ...
     </statefuls>

syntax Map ::= "@processStatefulOpts" "(" StatefulOptionals "," Map ")" [function]
rule @processStatefulOpts(.StatefulOptionals, M:Map) => M
rule @processStatefulOpts(direct : T:TableName ; Rest:StatefulOptionals, M:Map ) => @processStatefulOpts(Rest,  ("$table" |-> T) M["$binding" <- $direct])
rule @processStatefulOpts(static : T:TableName ; Rest:StatefulOptionals, M:Map ) => @processStatefulOpts(Rest,  ("$table" |-> T) M["$binding" <- $static])
rule @processStatefulOpts(instance_count : IC:UnsignedValue ; Rest:StatefulOptionals, M:Map ) => @processStatefulOpts(Rest, ("$instant_count" |-> USgnVal2Int(IC)) M ) //TODO(minor): IC should be ConstValue

syntax Map ::= "@processCounterOpts" "(" CounterOptionals "," Map ")" [function]
rule @processCounterOpts(.CounterOptionals, M:Map) => M
rule @processCounterOpts(min_width : MW:UnsignedValue ; Rest:CounterOptionals, M:Map ) => @processCounterOpts(Rest, ("$min_width" |-> USgnVal2Int(MW)) M) //TODO(minor): MW should be ConstValue
rule @processCounterOpts(saturating ; Rest:CounterOptionals, M:Map ) => @processCounterOpts(Rest, M["$saturating" <- true])

syntax Map ::= "@processMeterOpts" "(" MeterOptionals "," Map ")" [function]
rule @processMeterOpts(.MeterOptionals, M:Map) => M
rule @processMeterOpts(result : F:FieldRef ; Rest:MeterOptionals, M:Map ) => @processMeterOpts(Rest, ("$result" |-> F) M)

syntax Map ::=    "@processRegisterOpts" "(" RegisterOptionals "," Map ")" [function]
                | "@processRegisterOpts" "(" AttrEntries "," Map ")" [function]
rule @processRegisterOpts(.RegisterOptionals, M:Map) => M
rule @processRegisterOpts(attributes : A:AttrEntries ; Rest:RegisterOptionals, M:Map ) => @processRegisterOpts(Rest, @processRegisterOpts(A, M))
rule @processRegisterOpts(.AttrEntries, M:Map) => M
rule @processRegisterOpts(signed , Rest:AttrEntries, M:Map) => @processRegisterOpts(Rest, M["$signed" <- true])
rule @processRegisterOpts(saturating , Rest:AttrEntries, M:Map) => @processRegisterOpts(Rest, M["$saturating" <- true])


syntax KItem ::= "@addTableDirect" "(" Id ")"
rule <k> @addTableDirect(N:Id) => . ...</k>
     <statefuls> <stateful> <s-name> N </s-name> <s-opts> "$binding" |-> $direct "$table" |-> T:TableName _:Map </s-opts> ... </stateful> ... </statefuls>
     <tableDirects> T |-> ((.Set => SetItem(N)) _:Set) _:Map </tableDirects>

rule <k> @addTableDirect(N:Id) => . ...</k>
     <statefuls> <stateful> <s-name> N </s-name> <s-opts> "$binding" |-> $direct "$table" |-> T:TableName _:Map </s-opts> ... </stateful> ... </statefuls>
     <tableDirects> (.Map => (T |-> SetItem(N))) Rest:Map</tableDirects>
     when notBool #in_keys(T, Rest)

rule <k> @addTableDirect(N:Id) => . ...</k>
     <statefuls> <stateful> <s-name> N </s-name> <s-opts> "$binding" |-> B:BindingType _:Map</s-opts> ... </stateful> ... </statefuls>
     when B =/=K $direct


// syntax KItem ::= "@initStateful" "(" Id ")"
// init on first use

//action

rule <k> @processDec(action Name:ActionName ( Params:ParamList ) { Body:ActionStatements }  ) => . ... </k>
    <actions> (.Bag =>
          <action>
            <a-name> Name </a-name> <params> Params </params> <a-body> Body </a-body> ...
          </action>
    ) ... </actions>


// action profile
rule <k> @processDec(action_profile Name:ActionProfileName { Act:ActionSpecification Opt:ActionsProfileOptionals } ) => . ... </k>
     <actionProfiles>
        ( .Bag =>
            <actionProfile>
                <ap-name> Name </ap-name>
                <ap-acts> Act </ap-acts>
                <ap-opts> @processActionProfileOptionals(Opt, .Map) </ap-opts>
                ...
            </actionProfile>
        ) ...
     </actionProfiles>

syntax Map ::= "@processActionProfileOptionals" "(" ActionsProfileOptionals "," Map ")" [function]
rule @processActionProfileOptionals( .ActionsProfileOptionals , M:Map ) => M
rule @processActionProfileOptionals( size : S:UnsignedValue ; Rest:ActionsProfileOptionals , M:Map ) => @processActionProfileOptionals( Rest:ActionsProfileOptionals , ("$size" |-> USgnVal2Int(S) ) M:Map ) //TODO (minor) S should be ConstValue
rule @processActionProfileOptionals( dynamic_action_selection : S:SelectorName ; Rest:ActionsProfileOptionals , M:Map ) => @processActionProfileOptionals( Rest:ActionsProfileOptionals , ("$selector" |-> S ) M:Map )

rule <k> @processDec(action_selector Name:SelectorName { selection_key : FLC:FieldListCalculationName ; } ) => . ... </k>
     <actionSelectors>
        ( .Bag => <actionSelector> <as-name> Name </as-name> <key> FLC </key> ... </actionSelector>) ...
     </actionSelectors>

// table

rule table N:TableName { A:TableActions O:TableOptionals } => table N { reads { .FieldMatchs } A O } [macro]

rule <k> @processDec(table Name:TableName { reads { FM:FieldMatchs }  Act:TableActions Opt:TableOptionals } ) => . ... </k>
         <tables>... (.Bag =>
               <table>
                 <t-name> Name </t-name> <reads> FM </reads> <t-acts> Act </t-acts> <t-opts> Opt </t-opts> <rules> .List </rules> ...
               </table>
         ) ... </tables>


// control

rule <k> @processDec(control Name:ControlFunctionName { Body:ControlStatements } ) => . ... </k>
         <controlFlows> (.Bag =>
               <control>
                    <c-name> Name </c-name> <c-body> Body </c-body> ...
               </control>
         ) ...  </controlFlows>
	<cfset> (.Set => SetItem(Name)) _ </cfset> //TODO: //TODO: temporary fix for K issue #2279

//--------------------deparse order--------------------------


// assuming only dag or self loops with extract(hs[next]), refer to progress.txt
// really adhoc algorithm, but the semantics of deparsing is not clear

rule <k> @parseOrder(extract(H:InstanceName); Rest:ExtractOrSetStatements Ret:ReturnStatement) =>
            @if @is_marked(H) @then //#if H in P #then was not working correctly, probabely a bug in K
                @if @on_path(H) @then
                    .K
                @else
                    @addOnPath(H) ~> @parseOrder(Rest Ret)  ~> @removeOnPath(H)
                @fi
            @else
                @if @on_path(H) @then
                    $internal_error
                @else
                    @mark(H) ~> @addOnPath(H) ~> @parseOrder(Rest Ret) ~> @addOrder(H)  ~> @removeOnPath(H)
                @fi
            @fi
     ...
     </k>

rule <k> (@parseOrder(#parserState(C:ParserStateName)) => @if @is_state_marked(C) @then .K @else @mark_state(C) ~> @parseOrder(B) @fi) ... </k>
     <parserStates>
        <state> <ps-name> C </ps-name> <ps-body> B:ParserFunctionBody </ps-body> ... </state>
        ...
     </parserStates>

rule @parseOrder(_:SetStatement Rest:ExtractOrSetStatements Ret:ReturnStatement) => @parseOrder(Rest Ret)

rule @parseOrder(extract(H:InstanceName [ Idx:UnsignedValue ]); Rest:ExtractOrSetStatements Ret:ReturnStatement) => @parseOrder(extract($element(H,USgnVal2Int(Idx))); Rest Ret) //TODO(minor) Idx must be ConstValue
rule @parseOrder(extract(H:InstanceName [ next ]); Rest:ExtractOrSetStatements Ret:ReturnStatement) => @parseOrder(extract(H); Rest Ret)


rule @parseOrder(.ExtractOrSetStatements Ret:ReturnStatement) =>  @parseOrder(Ret)
rule <k> @parseOrder(return S:ParserStateName;) =>  @parseOrder(#parserState(S)) ... </k>
      <parserStates>
         <state> <ps-name> S  </ps-name> ... </state>
         ...
      </parserStates>
//rule <k> @parseOrder(return C:ControlFunctionName;) => . ... </k>
rule <k> @parseOrder(return C:Id;) => . ... </k>
      <controlFlows>
            <control> <c-name> C </c-name> ... </control>
            ...
      </controlFlows>
rule @parseOrder(return select ( _ ) { C:CaseEntries } ) =>  @parseOrder(C)
rule @parseOrder(.CaseEntries) =>  .K
rule @parseOrder(_:ValueList : C:CaseReturnValueType ; Rest:CaseEntries) =>
         @parseOrder(@caseReturnToReturn(C)) ~> @parseOrder(Rest) //dfs


syntax KItem ::= "@addOrder" "(" InstanceName ")"
rule <k> @addOrder(H:InstanceName) => . ... </k>
     <dporder> (.List => ListItem (H)) _:List  </dporder>

syntax KItem ::= "@on_path" "(" InstanceName ")"
rule <k> @on_path(H:InstanceName) => H in S ... </k>
     <onpath> S:Set </onpath>

syntax KItem ::= "@addOnPath" "(" InstanceName ")"
                | "@removeOnPath" "(" InstanceName ")"
rule <k> @addOnPath (H:InstanceName) => . ... </k>
     <onpath> (.Set => SetItem(H)) S:Set </onpath>
     when notBool H in S
rule <k> @removeOnPath (H:InstanceName) => . ... </k>
     <onpath> (SetItem(H) => .Set) _:Set </onpath>

syntax KItem ::= "@mark" "(" InstanceName ")"
rule <k> @mark (H:InstanceName) => . ... </k>
     <marked> <mheaders> (.Set => SetItem(H)) _:Set </mheaders> ... </marked>

syntax KItem ::= "@is_marked" "(" InstanceName ")"
rule <k> @is_marked(H:InstanceName) => H in S ... </k>
     <marked> <mheaders> S:Set </mheaders> ... </marked>


syntax KItem ::= "@mark_state" "(" ParserStateName ")"
rule <k> @mark_state (P:ParserStateName) => . ... </k>
     <marked> <mstates> (.Set => SetItem(P)) _:Set </mstates> ... </marked>

syntax KItem ::= "@is_state_marked" "(" ParserStateName ")"
rule <k> @is_state_marked(P:ParserStateName) => P in S ... </k>
     <marked> <mstates> S:Set </mstates> ... </marked>


// due to bug in K
//syntax Bool ::= "#in_set" "(" K "," Set ")" [function]
//rule #in_set(_:K, .Set) => false
//rule #in_set(X, SetItem(X) _:Set) => true
//rule #in_set(X, SetItem(Y) Rest:Set) => #in_set(X, Rest) when X =/=K Y

// -----------------------
rule <k> @fillInitInstances => .K ... </k>
     <instances> Init:Bag </instances>
     <initInstances> .K => Init </initInstances>
     <arrays> M:Map </arrays>
     <initArrays> _ => M </initArrays> //https://github.com/kframework/k/issues/2352

// --------------------init------------------------------------

// moved to initialization.k
rule  @exec => @nextPacket

// ------------------------packet to/from buffer-----------------------------

syntax KItem ::= "@nextPacket"
rule <k> @nextPacket =>
           @resetPerPacketState
        ~> @writeField(standard_metadata, ingress_port, @val(Port,32,false))
        ~> @parse&ingress
        ~> @ingressSpecialOperation
        ~> @egress
        ~> @egressSpecialOperation
        ~> @txenPacket
        ~> @nextPacket
     ... </k>
     <buffer> <in> (ListItem($packet(P:PacketData, Port:Int)) => .List) _:List </in> ... </buffer>
     <packet> _ => P </packet>
     <original> _=> P </original>

rule <k> @nextPacket =>
           @resetPerPacketState
        ~> @processInitFromPacket (Init)
        ~> @writeField(standard_metadata, ingress_port, @val(Port,32,false))
        ~> @parse&ingress
        ~> @ingressSpecialOperation
        ~> @egress
        ~> @egressSpecialOperation
        ~> @txenPacket
        ~> @nextPacket
     ... </k>
     <buffer> <in> (ListItem($packet(P:PacketData, Port:Int, Init:Map)) => .List) _:List </in> ... </buffer>
     <packet> _ => P </packet>
     <original> _=> P </original>

syntax KItem ::= "@txenPacket"
//syntax Id ::= "egress_spec" [token]
rule <k> @txenPacket => . ... </k>
     <packetout> P:List => .List </packetout>
     <buffer> <out>   _:List (.List => ListItem($packet(P,Port))) </out> ... </buffer>
      <instances>
          <instance>
              <i-name> standard_metadata </i-name>
              <fieldVals>  egress_spec |-> @val(Port:Int,_,_) ... </fieldVals>
              ...
          </instance>
          ...
      </instances>


syntax KItem ::= "@drop"
rule <k> @drop ~> _:K => @nextPacket </k>
     <packetout> _:List => .List </packetout>
//todo: unify @drop and parser_drop

syntax KItem ::= "@resetPerPacketState"
rule <k> @resetPerPacketState => .K ... </k>
     <instances> _:Bag => Init </instances>
     <initInstances> Init:Bag </initInstances>
     //<arrays> A:Map => #resetArrays(A,.Map) </arrays>
     <arrays> _ => M  </arrays>
     <initArrays> M:Map </initArrays>
     <pctx>
        <index> _ => 0 </index>
        <lastExt> _ => .K </lastExt>
        <varWidth> _ => .K </varWidth>
        <packetSize> _ => .K </packetSize>
     </pctx>
     <crnt> _ => .Map </crnt>
     <packetInit> _ => .Map </packetInit>

//https://github.com/kframework/k/issues/2352
//syntax KItem ::= "@resetArrays" "(" Set ")"
//rule <k> @resetArrays((SetItem(N:InstanceName) => .Set) _:Set) ... </k>
//     <arrays> (N |-> $array(_:Int , (_:Int => 0), (_:Int => -1))) _:Map </arrays>
//rule <k> @resetArrays(.Set) => .K ... </k>

// does not work for unknown reason
//syntax Map ::= "#resetArrays" "(" Map "," Map ")" [function]
//rule #restArrays(.Map,M:Map) => M
//rule #resetArrays((N:InstanceName |-> $array(S:Int,_,_)) R:Map, M:Map ) => #resetArrays(R, (N |-> $array(S,0,-1)) M)


syntax KItem ::= "@processInitFromPacket" "(" Map ")"
rule @processInitFromPacket(.Map) => .
rule @processInitFromPacket ((F:FieldRef |-> V:Val) Rest:Map) => @writeFieldAdjusted(F,V) ~>  @processInitFromPacket(Rest)




//--------------------parsing------------------------------
syntax KItem ::= "@parse&ingress" | "@egress"
rule <k> @parse&ingress => return start;  ... </k>
     <packet> P:PacketData </packet>
     <packetSize> _ => @calculatePacketSize(P , 0) </packetSize>

syntax Val ::= "@calculatePacketSize" "(" PacketData "," Int ")" [function]
rule @calculatePacketSize(.List, I:Int) => @val(I /Int 8, 0, false)
rule @calculatePacketSize(ListItem(@val(_,W:Int,_)) Rest:List, I:Int) => @calculatePacketSize(Rest, I +Int W)
rule @calculatePacketSize(S:String, 0) => @calculatePacketSize(.List, lengthString(S))

rule ESs:ExtractOrSetStatements R:ReturnStatement => ESs ~> R           [structural]
rule ES:ExtractOrSetStatement ESs:ExtractOrSetStatements => ES ~> ESs   [structural]

rule .ExtractOrSetStatements => .

//return to state
//TODO: check it is not control function name
rule <k> return State:ParserStateName ; => Body ... </k>
     <parserStates> <state>  <ps-name> State </ps-name> <ps-body> Body </ps-body> ... </state> ...</parserStates>
     <lastExt> _ => .K </lastExt>

//return to control function
rule <k> return Control:Id ; => @verifyCalcFields ~> Control(); ... </k>
    <controlFlows> <control> <c-name> Control </c-name> ... </control> ... </controlFlows>


//return parser_exception
rule <k> parse_error Exception:ParserExceptionName ; => @throw(Exception) ... </k>
     <exceptionHandlers> <exceptionHandler> <eh-name> Exception </eh-name> ... </exceptionHandler> ... </exceptionHandlers>

//return select

rule return select ( SE:SelectExp ) { CE:CaseEntries} => @select(@concat(@readFDRefs(SE)),CE)

syntax KItem ::= "@select" "(" KItem /* Val */ "," CaseEntries ")" [strict(1)]
rule @select (V:Val,  VL:ValueList : CA:CaseReturnValueType; Rest:CaseEntries )
    => @if @selected(V, VL) @then @caseReturnToReturn(CA) @else @select(V,Rest) @fi
rule @select (_:Val, .CaseEntries) => @throw(p4_pe_unhandled_select)

syntax KItem ::=    "@selected" "(" Val "," ValueList ")"
                  | "@selected" "(" Val "," Set ")"
rule @selected(_:Val, default ) => true
rule @selected(_:Val, .ValueOrMaskeds) => false
rule @selected(V:Val, F:FieldValue , Rest:ValueOrMaskeds) => @if @match(V,F,exact) @then true @else @selected(V,Rest) @fi
rule @selected(V:Val, F:FieldValue mask M:FieldValue , Rest:ValueOrMaskeds) => @if @match(V,@makePair(F,M),ternary) @then true @else @selected(V,Rest) @fi
rule <k> @selected(V:Val, N:ValueSetName , Rest:ValueOrMaskeds) => @if @selected(V,S) @then true @else @selected(V, Rest) @fi ... </k>
     <valueSets> <valueSet> <vs-name> N </vs-name> <vals> S:Set </vals> ... </valueSet> ... </valueSets>
rule @selected(_:Val, .Set) => false
rule @selected(V:Val, SetItem(F:Val) Rest:Set) => @if @match(V,F,exact) @then true @else @selected(V,Rest) @fi
rule @selected(V:Val, SetItem($pair(F:Val,M:Val)) Rest:Set) => @if @match(V,$pair(F,M),ternary) @then true @else @selected(V,Rest) @fi

//rule @select (Vs:Vals,  VM:ValueOrMaskeds : CA:CaseReturnValueType; Rest:CaseEntries )
//    => @selectCheckCase(Vs, @VMstoVals(VM), CA, Rest)
//rule @select (_:Vals, default : CA:CaseReturnValueType; _:CaseEntries) => @caseReturnToReturn(CA)

//syntax KItem ::= "@selectCheckCase" "(" Vals "," K /* Vals */ "," CaseReturnValueType "," CaseEntries  ")" [strict(2)]
//rule @selectCheckCase(Vs:Vals, Vss:Vals, CA:CaseReturnValueType, Rest:CaseEntries)
//    => @if @concat(Vs) %== @concat(Vss)  @then @caseReturnToReturn(CA) @else @select(Vs,Rest) @fi  //TODO: change this to == in Val when we have complete semantics for it

//syntax KItem /* Vals */ ::= "@VMstoVals" "(" ValueOrMaskeds ")"
//rule @VMstoVals (.ValueOrMaskeds) => @nil
//rule @VMstoVals (VM:ValueOrMasked , Rest:ValueOrMaskeds) => @makeCons(VM,@VMstoVals(Rest))
//wrong interpretion of the specification

syntax ReturnValueType ::= "@caseReturnToReturn" "(" CaseReturnValueType ")" [function]
rule @caseReturnToReturn(PS:ParserStateName) => return PS ;
//rule @caseReturnToReturn(CF:ControlFunctionName) => return CF ;
rule @caseReturnToReturn(parse_error PE:ParserExceptionName) => parse_error PE ;

//TODO: rule V:Val mask M:Val => ?
//TODO: rule VS:ValueSetName => ?



syntax KItem /* Vals */ ::= "@readFDRefs" "(" SelectExp ")"

rule @readFDRefs(.FieldOrDataRefs) => @nil
rule @readFDRefs(FDR:FieldOrDataRef , Rest:FieldOrDataRefs) => @makeCons(@readFDRef(FDR),@readFDRefs(Rest)) [structural]

syntax KItem /* Val */ ::= "@readFDRef" "(" FieldOrDataRef ")"
rule @readFDRef(F:FieldRef) => @readField(F)
rule <k> @readFDRef(latest . FN:FieldName) =>  @readField(H.FN) ... </k>
        <lastExt> H:InstanceName </lastExt>

rule <k> @readFDRef(current(O:UnsignedValue,W:UnsignedValue)) =>  @val ( String2Base(substrString(Packet, I +Int USgnVal2Int(O), I +Int USgnVal2Int(O) +Int USgnVal2Int(W) ),2) ,USgnVal2Int(W), false) ... </k>
     <packet> Packet:String </packet>
     <index> I:Int </index>
     when I +Int USgnVal2Int(O) +Int USgnVal2Int(W) <=Int lengthString(Packet)
//TODO(minor): I,W must be ConstValue
//TODO (minor) : current() for PacketData ::= List


//set metadata
rule set_metadata(I:InstanceName . F:FieldName , V:FieldValue) ; => @if @is_metadata(I) @then @writeFieldAdjusted(I,F,V) @else $compile_error @fi
rule set_metadata(I:InstanceName . F:FieldName , V:FieldOrDataRef) ; => @if @is_metadata(I) @then @writeFieldAdjusted(I,F,@readFDRef(V)) @else $compile_error @fi

syntax KItem ::= "@is_metadata" "(" InstanceName ")"
rule <k> @is_metadata(N:InstanceName) => B ... </k>
     <instances> <instance> <i-name> N </i-name> <metadata> B:Bool </metadata> ... </instance> ... </instances>

//extract
rule <k> extract(N:InstanceName [ I:UnsignedValue ] ) ;  => #if USgnVal2Int(I) <Int S #then  extract($element(N,USgnVal2Int(I))); #else @throw(p4_pe_index_out_of_bounds) #fi ... </k> //TODO (minor): I should be ConstValue
     <arrays> N |-> $array(S:Int,_:Int,_:Int) _:Map </arrays>
rule <k> extract(N:InstanceName [ next ]) ; => extract($element(N,Nx)); ... </k>
     <arrays> N |-> $array(S:Int,Nx:Int => Nx +Int 1,L:Int => maxInt(L,Nx)) _:Map </arrays> when Nx <Int S //TODO: "The keyword last can be used as an index to refer to the largest-index valid instance of a header stack." since in extraction there may be parser exception this thing max(L,Nx) is not technically correct, same about => Nx+!
rule <k> extract(N:InstanceName [ next ]) ; => @throw(p4_pe_index_out_of_bounds) ... </k>
     <arrays> N |-> $array(S:Int,Nx:Int,_:Int) _:Map </arrays> when Nx >=Int S

rule <k> extract (Name:InstanceName) ;  => @extract(Name,Fields) ... </k>
     <instances>
        <instance> <i-name> Name </i-name> <metadata> false </metadata> <typeName> Type:HeaderTypeName </typeName> ... </instance> ...
     </instances>
     <headers>
        <header> <h-name> Type </h-name>  <h-fields> Fields:FieldDecs </h-fields> ... </header> ...
     </headers>
//TODO ISSUE: what happens if a valid header gets extracted again?

syntax KItem ::= "@extract" "(" InstanceName "," FieldDecs ")"
rule <k> @extract(N:InstanceName, .FieldDecs) => . ... </k>
     <instances>
            <instance> <i-name> N </i-name>  <valid> false => true </valid> ... </instance> ...
     </instances>
     <lastExt> _ => N </lastExt>

rule @extract(N:InstanceName, F:FieldName : CW:ConstValue ( _:FieldMods ) ; Rest:FieldDecs ) =>
        @extractField(N,F,CW) ~> @extract(N,Rest)
rule <k> @extract(N:InstanceName, F:FieldName : * (_:FieldMods); Rest:FieldDecs) =>
    @if (@evalLengthExp(LE,N) %<= @val(ML,0,false)) @then
        @if ((@evalLengthExp(LE,N) %* @val(8,0,false)) %> @val(FW,0,false)) @then  //TODO (minor): it is actually >= but = may be problematic as width of 0 is currently interpreted as infinity
           @setVarWidth((@evalLengthExp(LE,N) %* @val(8,0,false)) %- @val(FW,0,false)) ~> @extractField(N,F,@getVarWidth) ~> @extract(N,Rest)
        @else
           @throw(p4_pe_header_too_short)
        @fi
    @else
        @throw(p4_pe_header_too_long)
    @fi
    ... </k>
    <instances>
        <instance> <i-name> N </i-name> <typeName> H:HeaderTypeName </typeName> ... </instance> ...
    </instances>
    <headers>
        <header> <h-name> H </h-name> <h-opts> ("length" |-> LE:LengthExp) ("$fixed_width" |-> FW:Int) ("max_length" |-> ML:Int) _:Map </h-opts>  ... </header> ...
    </headers>


syntax KItem ::= "@setVarWidth" "(" KItem /* Val */ ")" [strict]
rule <k> @setVarWidth(V:Val) => . ... </k>
     <parser> <varWidth> .K => V </varWidth> ... </parser>

syntax KItem ::= "@getVarWidth"
rule <k> @getVarWidth => V ... </k>
     <parser> <varWidth> V:Val </varWidth> ... </parser>

//syntax LengthExp ::= Val
syntax KItem ::= "@evalLengthExp" "(" LengthExp ","  InstanceName ")"
rule @evalLengthExp(CV:ConstValue, _:InstanceName) => CV
rule <k> @evalLengthExp(F:FieldName, N:InstanceName) => V ... </k>
    <instances>
        <instance> <i-name> N </i-name> <fieldVals> F |-> V:Val _:Map </fieldVals>  ... </instance> ...
    </instances>
rule @evalLengthExp(LE1:LengthExp * LE2:LengthExp, N:InstanceName) => @evalLengthExp(LE1, N) %* @evalLengthExp(LE2, N)
rule @evalLengthExp(LE1:LengthExp + LE2:LengthExp, N:InstanceName) => @evalLengthExp(LE1, N) %+ @evalLengthExp(LE2, N)
rule @evalLengthExp(LE1:LengthExp - LE2:LengthExp, N:InstanceName) => @evalLengthExp(LE1, N) %- @evalLengthExp(LE2, N)
rule @evalLengthExp(LE1:LengthExp << LE2:LengthExp, N:InstanceName) => @evalLengthExp(LE1, N) %<< @evalLengthExp(LE2, N)
rule @evalLengthExp(LE1:LengthExp >> LE2:LengthExp, N:InstanceName) => @evalLengthExp(LE1, N) %>> @evalLengthExp(LE2, N)

syntax KItem ::= "@extractField" "(" InstanceName "," FieldName "," KItem /* Val */ ")" [strict(3)]


rule <k> @extractField(N:InstanceName, F:FieldName , _:Val ) => @initField(N,F,@extractFieldValFromPacket(@packetAt(Packet, I) , @getAttr(F,Fs))) ... </k>
     <instances>
        <instance> <i-name> N </i-name>  <typeName> H:HeaderTypeName </typeName>  ... </instance>
        ...
     </instances>
     <headers>
              <header> <h-name> H </h-name> <h-fields> Fs:FieldDecs </h-fields> ... </header>
              ...
     </headers>
     <packet> Packet:List </packet>
     <index> I:Int => I +Int 1 </index>
     when I <Int size(Packet)
     //when U <Int size(Packet)
     //bug with K's build-in size(List)


rule <k> @extractField(N:InstanceName, F:FieldName , @val(W:Int,_,_) ) => @initField(N,F,@extractFieldValFromPacket(@val(String2Base(substrString(Packet, I, I +Int W),2),W,false) , @getAttr(F,Fs))) ... </k>
     <instances>
        <instance> <i-name> N </i-name>  <typeName> H:HeaderTypeName </typeName>  ... </instance>
        ...
     </instances>
     <headers>
              <header> <h-name> H </h-name> <h-fields> Fs:FieldDecs </h-fields> ... </header>
              ...
     </headers>
     <packet> Packet:String </packet>
     <index> I:Int => I +Int W </index>
     when I +Int W <=Int lengthString(Packet)

rule <k> @extractField(_:InstanceName, _:FieldName , _:Val ) => @throw(p4_pe_out_of_packet) ... </k>
     <packet> Packet:List </packet>
     <index> I:Int </index>
     when I >=Int size(Packet)

rule <k> @extractField(_:InstanceName, _:FieldName , @val(W:Int,_,_) ) => @throw(p4_pe_out_of_packet) ... </k>
     <packet> Packet:String </packet>
     <index> I:Int </index>
     when I +Int W >Int lengthString(Packet)

//bug with K's build-in size(List)
syntax Int ::= "#listSize" "(" List ")" [function]
rule #listSize(.List) => 0
rule #listSize(ListItem(_) L:List) => 1 +Int #listSize(L)



syntax Val ::= "@packetAt" "(" List ","  Int ")" [function]
rule @packetAt(ListItem(X) _:List, 0) => X
rule @packetAt(ListItem(_) Rest:List, I:Int) => @packetAt(Rest, I -Int 1) when I >Int 0

syntax KItem ::=   "@writeFieldAdjusted" "(" KItem /*ResolvedHeaderRef */ "," FieldName "," KItem /* Val */ ")" [strict(1,3)]
                 | "@writeFieldAdjusted" "(" FieldRef "," KItem /* Val */ ")" [strict(2)]
rule @writeFieldAdjusted( I:HeaderRef . F:FieldName, V:Val) => @writeFieldAdjusted(I,F,V)
rule <k> @writeFieldAdjusted($href(N:InstanceName),F,V:Val) => @writeField(N,F,@adjustVal(@getAttr(F,Fs),V)) ...</k>
          <instances>
             <instance> <i-name> N </i-name>  <typeName> H:HeaderTypeName </typeName>  ... </instance>
             ...
          </instances>
          <headers>
            <header> <h-name> H </h-name> <h-fields> Fs:FieldDecs </h-fields> ... </header>
            ...
          </headers>

syntax KItem ::= "@writeField" "(" InstanceName "," FieldName "," KItem /* Val */ ")" [strict(3)]
rule <k> @writeField(N,F,V:Val) => . ...</k>
        <instances>
            <instance> <i-name> N </i-name> <valid> true </valid>  <fieldVals> FV:Map => FV [ F <- V ] </fieldVals>  ... </instance>
            ...
        </instances>

rule <k> @writeField(N,_,_:Val) => . ...</k>
        <instances>
            <instance> <i-name> N </i-name> <valid> false </valid>  ... </instance>
            ...
        </instances>
//no change if the field is not valid

//TODO: change FieldDec to FieldAttr which should be custom format for field attributes
syntax FieldDec ::= "@getAttr" "(" FieldName "," FieldDecs ")" [function]
rule @getAttr (F:FieldName, F : W:BitWidth ( M:FieldMods ); _:FieldDecs) => F : W (M);
rule @getAttr (F1:FieldName, F2:FieldName : _:BitWidth ( _:FieldMods ); Rest:FieldDecs) =>
        @getAttr(F1,Rest) when  F1 =/=K F2

syntax KItem /* Val */ ::= "@adjustVal" "(" FieldDec "," KItem /* Val */ ")" [strict(2)]
rule @adjustVal( _:FieldName : Wd:UnsignedValue ( FM:FieldMods ) ;, V:Val )  //TODO (minor) : Wd should be ConstValue
    => @adjustVal(USgnVal2Int(Wd),@isSigned(FM),@isSaturating(FM), V)
rule <k> @adjustVal (_:FieldName : * ( FM:FieldMods ) ;, V:Val) => @adjustVal(W,@isSigned(FM),@isSaturating(FM), V) ...</k>
     <varWidth> @val(W:Int,_,_) </varWidth>

syntax KItem /* Val */ ::= "@adjustVal" "(" Map "," KItem /* Val */ ")" [strict(2)]
rule @adjustVal("$width" |-> W:Int "$signed" |-> Sg:Bool "$saturating" |-> St:Bool _:Map , V:Val) => @adjustVal(W,Sg,St,V)

syntax KItem /* Val */ ::= "@adjustVal" "(" Int "," Bool "," Bool "," KItem /* Val */ ")" [strict(4)]
rule @adjustVal(W2:Int,Sg2:Bool,_St:Bool,@val(V,_W1,_Sg1)) =>
       @val(V,W2,Sg2)
//TODO: (VERY IMPORTANT ***): fix and complete this ***************************************

syntax Bool ::= "@isSigned" "(" FieldMods ")" [function]
rule @isSigned(.FieldMods) => false
rule @isSigned(signed , _:FieldMods) => true
rule @isSigned(saturating , Rest:FieldMods) => @isSigned(Rest:FieldMods)


syntax Bool ::= "@isSaturating" "(" FieldMods ")" [function]
rule @isSaturating(.FieldMods) => false
rule @isSaturating(saturating , _:FieldMods) => true
rule @isSaturating(signed , Rest:FieldMods) => @isSigned(Rest:FieldMods)

//syntax KItem /* Val */ ::= "@String2FieldVal" "(" String "," FieldDec ")"
//rule @String2FieldVal( S:String , _:FieldName : Wd:UnsignedValue ( _:FieldMods ) ;)
//    => @val(String2Base(S,2),USgnVal2Int(Wd),false)
syntax KItem /* Val */ ::= "@extractFieldValFromPacket" "(" Val "," FieldDec ")"
rule @extractFieldValFromPacket( @val(V:Int,W:Int,S:Bool) , _:FieldName : Wd:UnsignedValue ( _:FieldMods ) ;)
    => @val(V,W,S)  when W ==Int USgnVal2Int(Wd)
                                 //    => @val(String2Base(S,2),USgnVal2Int(Wd),false)
//TODO: IMPORTANT: fix and complete this
rule <k> @extractFieldValFromPacket( @val(V:Int,W:Int,S:Bool) , _:FieldName : * ( _:FieldMods ) ;)
    => @val(V,W,S) ... </k>
    <parser> <varWidth> @val(Wd:Int,_,_) </varWidth> ... </parser>
    when W ==Int Wd

//----------------exception handler------------------------

syntax KItem ::= "@throw" "(" ParserExceptionName ")"
rule <k> @throw(E:ParserExceptionName) => S ~> R ... </k>
     <exceptionHandlers>
        <exceptionHandler> <eh-name> E </eh-name> <pebody> <setsts> S:SetStatements </setsts> <return> R:ReturnOrDrop </return> ... </pebody> </exceptionHandler>
     ...
     </exceptionHandlers>
     //TODO: set some metadata for the packet

rule <k> @throw(E:ParserExceptionName) => #if p4_pe_default in S #then @throw(p4_pe_default) #else @throw($unhandled_exception) #fi  ... </k>
     <handledExceptions> S:Set </handledExceptions>
     when notBool E in S andBool E =/=K $unhandled_exception

rule @throw($unhandled_exception) => parser_drop //TODO: actually change it an exception handler that sets some relevant metadata

rule .SetStatements => .K                           [structural]
rule S:SetStatement Rest:SetStatements => S ~> Rest [structural]


rule return X => return X;

rule <k> parser_drop ~> _:K => @nextPacket </k>
// what else TODO?

syntax Id ::=
          "p4_pe_index_out_of_bounds"   [token]
        | "p4_pe_out_of_packet"         [token]
        | "p4_pe_header_too_long"       [token]
        | "p4_pe_header_too_short"      [token]
        | "p4_pe_unhandled_select"      [token]
        | "p4_pe_checksum"              [token]
        | "p4_pe_default"               [token]
        | "$unhandled_exception"        [token]

//----------------verify/update calc fields------------------
//verify
syntax KItem ::=   "@verifyCalcFields"
                 | "@verifyCalcFields" "(" KItem ")"

rule <k> @verifyCalcFields => @verifyCalcFields(S) ... </k>
     <calcFieldSet> S:Set </calcFieldSet>

rule @verifyCalcFields(.Set) => .
rule @verifyCalcFields(SetItem(F:FieldRef) Rest:Set) => @verifyCalcField(F) ~> @verifyCalcFields(Rest)


syntax KItem ::=   "@verifyCalcField" "(" FieldRef ")"
                 | "@verifyCalcField" "(" FieldRef "," List ")"
                 | "@verifyCalcField" "(" KItem /* ResolvedHeaderRef */ "," FieldName ")" [strict(1)]




rule @verifyCalcField(H:HeaderRef . F:FieldName) => @verifyCalcField(H, F)
rule <k> @verifyCalcField($href(H:InstanceName) , _:FieldName) => .  ... </k>
     <instances> <instance> <i-name> H </i-name> <valid> false </valid> ... </instance> ... </instances>
rule <k> @verifyCalcField($href(H:InstanceName) , F:FieldName) => @verifyCalcField(H.F, V)  ... </k>
         <instances> <instance> <i-name> H </i-name> <valid> true </valid> ... </instance> ... </instances>
         <calcFields> <calcField> <fieldRef> H.F </fieldRef> <verifies> V:List </verifies> ... </calcField> ... </calcFields>

rule @verifyCalcField(_:FieldRef, .List) => .
rule @verifyCalcField(F:FieldRef, ListItem(verify FLC:FieldListCalculationName if (C:CalcBoolCond);) Rest:List) =>
        @if (C) @then
            (@if (F %== @calculateFLC(FLC)) @then //probably should check width
                .K
             @else
                //@throw(p4_pe_checksum)
                // TODO: right now the checksum is a dummy number, so now throwing exceptions
                .K
             @fi
            )
        @else
            @verifyCalcField(F, Rest)
        @fi

//rule CalcBCEq(F:FieldRef, V:FieldValue) => V %== F
rule F:FieldRef == V:FieldValue => V %== F
//rule CalcBCValid(H:HeaderOrFieldRef) => @isValid(H)
rule valid(H:HeaderOrFieldRef) => @isValid(H)

syntax KItem ::= "@calculateFLC" "(" FieldListCalculationName ")"
rule <k> @calculateFLC(N:FieldListCalculationName) => @calculateChecksum(@concat(@readFieldList(E)), A, W) ... </k>
     <fieldListCalcs> <fieldListCalc> <flc-name> N </flc-name> <fLists> L:List </fLists> <algorithm> A:StreamFunctionAlgorithmName </algorithm> <outWidth> W:Int </outWidth> <fListIndex> I:Int </fListIndex> ... </fieldListCalc> ... </fieldListCalcs>
     <fieldLists> <fieldList> <fl-name> FN:FieldListName </fl-name> <fl-fields> E:FieldListEntryItems </fl-fields> ... </fieldList> ... </fieldLists>
     when L[I] ==K ListItem(FN)


syntax KItem ::=   "@readFieldList" "(" FieldListEntryItems ")"

rule @readFieldList(.FieldListEntryItems) => @nil
rule @readFieldList(F:FieldRef ; Rest:FieldListEntryItems) => @if @isValid(F) @then @makeCons(@readField(F), @readFieldList(Rest)) @else @readFieldList(Rest) @fi
rule @readFieldList(V:FieldValue ; Rest:FieldListEntryItems) => @makeCons(V, @readFieldList(Rest))
rule <k> @readFieldList(N:FieldListName ; Rest:FieldListEntryItems) => @makeConcat(@readFieldList(E),@readFieldList(Rest)) ... </k>
     <fieldLists> <fieldList> <fl-name> N </fl-name> <fl-fields> E:FieldListEntryItems </fl-fields> ... </fieldList> ... </fieldLists>
rule <k> @readFieldList(N:InstanceName ; Rest:FieldListEntryItems) => @readFieldList(@getFieldsAsFLI(N,F,Rest)) ... </k> //todo: array
     <instances> <instance> <i-name> N </i-name> <typeName> H:HeaderTypeName </typeName> ...   </instance> ... </instances>
     <headers> <header> <h-name> H </h-name> <h-fields> F:FieldDecs </h-fields> ... </header> ... </headers>
//TODO rule @readFieldList(payload ; Rest:FieldListEntryItems) => @makeCons(V, @readFieldList(Rest))


syntax FieldListEntryItems ::= "@getFieldsAsFLI" "(" HeaderRef "," FieldDecs ","  FieldListEntryItems ")" [function]
rule @getFieldsAsFLI(H:HeaderRef , F:FieldName : _:BitWidth  ( _:FieldMods ); Rest:FieldDecs, FLI:FieldListEntryItems) => @getFieldsAsFLI(H,Rest, H.F ; FLI)
rule @getFieldsAsFLI(_:HeaderRef , .FieldDecs , FLI:FieldListEntryItems) => FLI

syntax KItem ::= "@calculateChecksum" "(" KItem /* Val */ "," StreamFunctionAlgorithmName "," Int ")" [strict(1)]
//TODO: fix this, need to create a hook in k
//rule @calculateChecksum (_:Val,_:StreamFunctionAlgorithmName,W:Int) => @val(0,W,false)
syntax Id ::= "csum16" [token]
rule @calculateChecksum (@val(V:Int,Wi:Int,false),csum16,Wo:Int) => @val(#csum16(V,Wi,Wo),Wo,false)

//update

syntax KItem ::=   "@updateCalcField" "(" FieldRef "," List "," Val ")"

rule @updateCalcField(_:FieldRef, .List, V:Val) => V
rule @updateCalcField(F:FieldRef, ListItem(update FLC:FieldListCalculationName if (C:CalcBoolCond);) Rest:List, V:Val) =>
        @if (C) @then
            @calculateFLC(FLC)
        @else
            @updateCalcField(F, Rest, V)
        @fi
//----------------control flow-------------------------
rule .ControlStatements => .                                [structural]
rule S:ControlStatement Rest:ControlStatements => S ~> Rest [structural]
rule { B:ControlStatements } => @setCrnt("$action", "%nothing") ~> @setCrnt("$miss", "%nothing") ~> B


//apply
rule apply (T:TableName) ; => apply (T) { .HitMissCases }   //[macro]


//TODO: for now assuming that a snapshot of current rules are taken before matching
rule <k> apply (T:TableName) { C:CaseList } => @setCrnt("$table", T) ~> @checkNextRule(FM,R) ~> @setCrnt("$table", "%nothing") ~> @checkNextAppSelCase (C) ... </k>
     <tables>
        <table> <t-name> T </t-name> <reads> FM:FieldMatchs </reads> <rules> R:List </rules> ... </table>
     ...
     </tables>

//select

syntax KItem ::= "@checkNextAppSelCase" "(" CaseList ")"
rule @checkNextAppSelCase(.ActionCases) => .
rule @checkNextAppSelCase(.HitMissCases) => .
rule <k> @checkNextAppSelCase(HM:HitOrMiss B:ControlBlock Rest:HitMissCases) =>
        #if ((HM ==K miss andBool MS ==K true ) orBool (HM ==K hit andBool MS =/=K true)) #then
            B
        #else
            @checkNextAppSelCase(Rest)
        #fi
     ...
     </k>
     <crnt> ("$miss" |-> MS:Bool)  _:Map </crnt>

rule <k> @checkNextAppSelCase(AD:ActionOrDefault B:ControlBlock Rest:ActionCases) =>
       //#if (@isDefault(AD) orBool A ==K AD) #then  https://github.com/p4lang/p4-spec/issues/447
       #if ((@isDefault(AD) andBool A =/=K "%nothing")  orBool A ==K AD) #then
           B
       #else
           @checkNextAppSelCase(Rest)
       #fi
     ...
     </k>
     <crnt> ("$action" |-> A:KItem)  _:Map </crnt>

syntax Bool ::= "@isDefault" "(" ActionOrDefault ")" [function]
rule @isDefault(default) => true
rule @isDefault(_:ActionName) => false
/*TODO ISSUE: Just to make sure: if a default action in a table is defined and
                the default action is taken, 1) is it a hit or miss? 2) does the default case
                in a apply and select block gets gets elected?
                If nothing matches in the table and there is no default action, does the default case
                in a apply and select block gets gets elected?
*/

//if
rule if ( B:BoolExpr ) C:ControlBlock Rest:ControlStatements => if ( B ) C else { .ControlStatements } Rest  [macro]
rule else I:IfElseStatement => else { I } [macro]

rule if ( B:BoolExpr ) T:ControlBlock else F:ControlBlock =>
        @if B @then T @else F @fi

syntax Id ::= "ingress" [token]
//call
rule <k> F:ControlFunctionName () ; => @if (F ==K ingress) andBool T ==K @egress_clone @then . @else Body @fi  ... </k>
     <controlFlows>
        <control> <c-name> F </c-name> <c-body> Body </c-body> ... </control>
        ...
     </controlFlows>
     <instances> <instance> <i-name> standard_metadata </i-name> <fieldVals> (instance_type |-> T:Val) _:Map </fieldVals> ... </instance> ... </instances>
//should distinguish between action call with zero arguments and control function call
//UPDATE: it is disinguishable because the former is Id ( .Args ) ; the later is Id () ;


//-----------------expr and boolean expr---------------

rule F:FieldRef => @readField(F)

syntax Exp ::= Val
syntax BoolExpr ::= Bool

rule @val(V1,_,_) == @val(V2,_,_) => V1 ==Int V2
rule @val(V1,_,_) != @val(V2,_,_) => V1 =/=Int V2
rule @val(V1,_,_) > @val(V2,_,_) => V1 >Int V2
rule @val(V1,_,_) >= @val(V2,_,_) => V1 >=Int V2
rule @val(V1,_,_) < @val(V2,_,_) => V1 <Int V2
rule @val(V1,_,_) <= @val(V2,_,_) => V1 <=Int V2
//TODO: is there any problem if width/signedness is different?


rule @val(V1,_,_) + @val(V2,_,_) => @val(V1 +Int V2,0,true)
rule @val(V1,_,_) * @val(V2,_,_) => @val(V1 *Int V2,0,true)
rule @val(V1,_,_) - @val(V2,_,_) => @val(V1 -Int V2,0,true)
rule @val(V1,_,_) << @val(V2,_,_) => @val(V1 <<Int V2,0,true)
rule @val(V1,_,_) >> @val(V2,_,_) => @val(V1 >>Int V2,0,true)
rule @val(V1,_,_) & @val(V2,_,_) => @val(V1 &Int V2,0,true)
rule @val(V1,_,_) | @val(V2,_,_) => @val(V1 |Int V2,0,true)
rule @val(V1,_,_) ^ @val(V2,_,_) => @val(V1 xorInt V2,0,true) //^Int is power but in c, ^ means xor
//rule NotExp(@val(V2,_,_)) => @val(~Int V2,0,true)
rule ~ @val(V2,_,_) => @val(~Int V2,0,true)
// TODO ISSUE: the semantics of none of these operators is exactly
// defined specially when it comes to width, so leaving it like this
// for now.

//rule MinusExp(@val(V:Int,0,_)) =>  @val(0 -Int V,0,true)
//rule MinusExp(@val(V:Int,W,_)) =>  @val(0 -Int V,W +Int 1,true) when W >Int 0
//TODO: unify it with @negative

//rule BExpValid( H:HeaderRef )   => @isValid(H)
rule valid(H:HeaderRef):BoolExpr =>  @isValid(H)
//rule BExpPar(BE:K) => BE
rule not B:Bool => notBool B

rule B1:Bool or B2:Bool => B1 orBool B2
rule B1:Bool and B2:Bool => B1 andBool B2
//TODO ISSUE: short circuit ? doesn't matter because no side effect

//---------------table match-----------------------------
syntax KItem ::= "@checkNextRule" "(" FieldMatchs "," List /*rules*/ ")"

//TODO: assumming rules are checked for consistency at the time of insertion and are  are sorted by their priority



// miss
//syntax Int ::= "$default_entry_index" [token]
rule <k> @checkNextRule(_:FieldMatchs,.List  ) => @setCrnt("$rule", "%nothing") ~> @setCrnt("$miss", true) ~> @callOrDeref(A) ~> @setCrnt("$rule", "%nothing") ... </k>
     <crnt> ("$table" |-> T:TableName) _:Map </crnt>
     <tables> <table> <t-name> T </t-name> <default> A:ActionCallOrActionProfileRef </default> ... </table> ... </tables>
rule <k> @checkNextRule(_:FieldMatchs,.List  ) => @setCrnt("$miss", true) ... </k>
     <crnt> ("$table" |-> T:TableName) _:Map </crnt>
     <tables> <table> <t-name> T </t-name> <default> .K </default> ... </table> ... </tables>


rule @checkNextRule(FM:FieldMatchs, ListItem($rule(Id:Int, $ctr(R:List),CD:ActionCallOrActionProfileRef )) Rest:List)
    => @if @matchAll(FM,R) @then @setCrnt("$miss", false) ~> @setCrnt("$rule", Id) ~> @updateDirectStatefuls ~> @callOrDeref(CD) ~> @setCrnt("$rule", "%nothing")  @else @checkNextRule(FM,Rest) @fi

//rule A:ActionName ~> @setCrntRule(.K) => @setCrntRule(A) ~> A

syntax KItem /* Bool */ ::= "@matchAll" "(" FieldMatchs "," List /*criteria*/  ")"
rule @matchAll(.FieldMatchs,.List) => true
rule @matchAll(FMR:FieldOrMaskedRef : MT:FieldMatchType ; R1:FieldMatchs, ListItem(V:KItem) R2:List)
    => @match(@readFMRef(FMR,MT),V,MT) %&& @matchAll(R1,R2)

syntax KItem /* Bool */ ::= "@match" "(" KItem /* KResult */ "," KItem /* KResult */ "," FieldMatchType  ")" [strict(1,2)]
rule @match(V1:Val,V2:Val,exact) => V1 == V2    //TODO ISSUE: is this it?
rule @match(V1:Val,$pair(V2:Val,M:Val),ternary) => (V1 & M) == (V2 & M)
rule @match(V1:Val,$pair(V2:Val,M:Val),lpm) => (V1 & M) == (V2 & M)
rule @match(V1:Val,$pair(L:Val,H:Val),range) => (V1 >= L) and (V1 <= H)
//rule @match(B1:Bool,B2:Bool,valid) => B1 ==Bool B2
rule @match(B:Bool => @BoolToVal(B),_,valid)
rule @match(_,B:Bool => @BoolToVal(B),valid)
rule @match(V1:Val,V2:Val,valid) => V1 == V2

syntax KItem /* KResult */ ::= "@readFMRef" "(" FieldOrMaskedRef "," FieldMatchType  ")"


rule @readFMRef(F:FieldRef,FM:FieldMatchType) => #if FM =/=K valid #then @readField(F) #else @BoolToVal(@isValid(F)) #fi
rule @readFMRef(F:FieldRef mask M:ConstValue,_)  => @applyMask(@readField(F),M)
// "Header references for matching may only be used with the valid match type."
rule @readFMRef(H:HeaderRef,valid) => @BoolToVal(@isValid(H))
rule @readFMRef(H:HeaderRef . valid,_) => @BoolToVal(@isValid(H)) //since v1.0.4


syntax KItem ::= "@BoolToVal" "(" KItem /* Bool */ ")" [strict]
rule @BoolToVal(true) => @val(1,0,false)
rule @BoolToVal(false) => @val(0,0,false)


syntax KItem ::= "@setCrnt" "(" KItem "," KItem ")"
rule <k> @setCrnt(K:KItem, V:KItem) => .K ... </k>
     <crnt> M:Map => M[K <- V] </crnt>

//--------------statefuls--------------------------------

syntax KItem ::=  "@updateDirectStatefuls"
                | "@updateDirectStatefuls" "(" KItem /* ::Set */ ")"
rule <k> @updateDirectStatefuls => @updateDirectStatefuls(S) ... </k>
     <tableDirects> T |-> S:Set _:Map </tableDirects>
     <crnt> ("$table" |-> T:TableName) _:Map </crnt>
rule <k> @updateDirectStatefuls => .K ... </k>
     <tableDirects> M:Map </tableDirects>
     <crnt> ("$table" |-> T:TableName) _:Map </crnt>
     when notBool #in_keys(T,M)
rule <k> (.K => @updateCounter(N, CR)) ~> @updateDirectStatefuls((SetItem(N:Id) => .Set) _:Set) ... </k>
      <statefuls> <stateful> <s-name> N </s-name> <stype> $counter </stype> ... </stateful> ... </statefuls>
      <crnt> ("$rule" |-> CR:Int) _:Map </crnt>
rule <k> (.K => @updateMeter(N, CR, FR)) ~> @updateDirectStatefuls((SetItem(N:Id) => .Set) _:Set) ... </k>
     <statefuls> <stateful> <s-name> N </s-name> <stype> $meter </stype> <s-opts> ("$result" |-> FR:FieldRef) _:Map </s-opts> ... </stateful> ... </statefuls>
     <crnt> ("$rule" |-> CR:Int) _:Map </crnt>
/*rule <k> @updateDirectStatefuls(SetItem(N:Id) Rest:Set) => #if (T ==K $counter) #then @updateCounter(N, CR) #else @updateMeter(N, CR, #castToFieldRef(M["$result"])) #fi ~> @updateDirectStatefuls(Rest) ... </k>
      <statefuls> <stateful> <name> N </name> <stype> T:StatefulType </stype> <opts> M:Map </opts> ... </stateful> ... </statefuls>
      <crntRule> CR:Int </crntRule>
      when (T ==K $meter) impliesBool #in_keys("$result", M) //the result attribute is required if a meter is declared with the direct attribute*/
      //does not work for unknown reason


rule @updateDirectStatefuls(.Set) => .

syntax KItem ::= "@updateCounter" "(" Id "," Int ")"
rule <k> @updateCounter (C:Id , I:Int) => @writeStatefulAdjusted(C, I, @readStateful(C, I) %+ #if (T ==K #token("packets","CounterType")) #then @val(1,0,false) #else S #fi) ... </k>
     <statefuls> <stateful> <s-name> C </s-name> <s-opts> "$counter_type" |-> T:CounterType _:Map </s-opts> ... </stateful> ... </statefuls>
     <packetSize> S:Val </packetSize>

syntax KItem ::=  "@updateMeter" "(" Id "," Int "," FieldRef")"
rule @updateMeter(M:Id, I:Int , F:FieldRef) => @writeStatefulAdjusted(M, I, @doUpdateMeter(M, I)) ~> @if @isValid(F) @then @writeFieldAdjusted(F, @readStateful(M,I)) @else .K @fi


syntax KItem ::= "@doUpdateMeter" "(" Id "," Int ")"
rule @doUpdateMeter(_,_) => @val(0,2,false)
//TODO (minor): doing nothing for the meter

syntax KItem ::= "@writeStatefulAdjusted" "(" Id "," Int "," KItem /*Val*/ ")" [strict(3)]
rule <k> @writeStatefulAdjusted(N:Id, I:Int, V:Val) => @writeStateful(N, I, @adjustVal(Opts["$width" <- W],V)) ... </k>
      <statefuls> <stateful> <s-name> N </s-name> <s-opts> Opts:Map </s-opts> <width> W:Int </width> ... </stateful> ... </statefuls>

syntax KItem ::= "@writeStateful" "(" Id "," Int "," KItem /*Val*/ ")" [strict(3)]
rule <k> @writeStateful (N:Id, I:Int, V:Val) => . ... </k>
     <statefuls> <stateful> <s-name> N </s-name> <stfvals> M => M [I <- V] </stfvals> ... </stateful> ... </statefuls>

syntax KItem /* Val */ ::= "@readStateful" "(" Id "," Int ")"
rule <k> @readStateful (N:Id, I:Int) =>  V  ... </k>
     <statefuls> <stateful> <s-name> N </s-name> <stfvals> (I |-> V:Val) _:Map </stfvals> ... </stateful> ... </statefuls>
rule <k> @readStateful (N:Id, I:Int) => @writeStatefulAdjusted(N, I, @val(0,0,false)) ~> @readStateful(N, I) ... </k>          //TODO ISSUE: what should be inital value of meters and registers? for now, assuming 0
     <statefuls> <stateful> <s-name> N </s-name> <stfvals> M:Map </stfvals> <width> _:Int </width> <s-opts> _:Map </s-opts> ... </stateful>  ... </statefuls>
     when notBool #in_keys(I,M)



//K's in_keys is not implemented
syntax Bool ::= "#in_keys" "(" KItem "," Map ")" [function]
rule #in_keys(_:KItem, .Map) => false
rule #in_keys(K1:KItem, (K1 |-> _V:KItem) _:Map) => true
rule #in_keys(K1:KItem, (K2:KItem |-> _V:KItem) Rest:Map) => #in_keys(K1,Rest) when K1 =/=K K2

//---------------actions----------------------------------
//syntax Arg ::= Val
syntax KItem ::= "@resolveArgs" "(" Args "," ResolvedArgs ")"
rule @resolveArgs(.Args,R:ResolvedArgs) => R
rule @resolveArgs((FR:FieldRef , Rest:Args) => Rest,$resolved(_:List (.List => ListItem(FR))))  //we do not evaluate fieldref
rule @resolveArgs(F:FieldValue , Rest:Args,R:ResolvedArgs) => F ~> @resolveArgs(Rest,R)  //a workaround
rule (V:Val => .) ~> @resolveArgs(_:Args,$resolved(_:List (.List => ListItem(V))))

//rule <k> (.K => H) ~> @resolveArgs(H:HeaderRef , _:Args, _:ResolvedArgs) ... </k> //clash with Id
rule <k> (.K => H[I]) ~> @resolveArgs(H:InstanceName [ I:Index ] , _:Args, _:ResolvedArgs) ... </k>
rule (RH:ResolvedHeaderRef => .K) ~> @resolveArgs((_:HeaderRef , Rest:Args) => Rest, $resolved(_:List (.List => ListItem(RH))))
rule <k> @resolveArgs((X:Id , Rest:Args) => Rest,$resolved(_:List (.List => ListItem($aref(X))))) ... </k>
     <arrays>  (X |-> _:KItem)  _:Map </arrays>

rule <k> @resolveArgs((X:Id , Rest:Args) => Rest,$resolved(_:List (.List => ListItem(V)))) ... </k>
     <frameStack> ListItem((X |-> V) _:Map) _:List </frameStack>
rule <k> @resolveArgs((X:Id , Rest:Args) => Rest,$resolved(_:List (.List => ListItem(X)))) ... </k>
     <instances> <instance> <i-name> X </i-name> ... </instance> ... </instances>
     <frameStack> ListItem(M:Map) _:List </frameStack> when notBool (X in keys(M))
rule <k> @resolveArgs((X:Id , Rest:Args) => Rest, $resolved(_:List (.List => ListItem(X)))) ... </k>
     <statefuls> <stateful> <s-name> X </s-name> ... </stateful> ... </statefuls>





//compound actions
rule <k> @call( A:ActionName , $resolved(Ag) ) => @pushstack ~> @bindParams(P,Ag) ~> B ~> @popstack ... </k>
     <actions>
        <action> <a-name> A </a-name> <params> P:ParamList </params> <a-body> B:ActionStatements </a-body> ... </action>
        ...
     </actions>


syntax KItem ::= "@bindParams" "(" ParamList "," List ")"
rule @bindParams(.ParamList, .List) => .
rule <k> @bindParams((P:ParamName , PR:ParamList), ListItem(A) AR:List) => @bindParams(PR,AR) ... </k>
     <frameStack> ListItem(M:Map => M [P <- A]) _:List  </frameStack>
    //TODO (CHECK): check action does not have same parameters


syntax KItem ::= "@popstack" | "@pushstack"
rule <k> @pushstack => . ...</k>
     <frameStack>  (.List => ListItem(.Map)) _:List  </frameStack>
rule <k> @popstack => . ...</k>
     <frameStack> (ListItem(_:Map) => .List) _:List </frameStack>


rule A:ActionStatement Rest:ActionStatements => A ~> Rest   [structural]
rule .ActionStatements => .                                 [structural]


rule A:ActionName ( Ag:Args ) ; => @call(A,@resolveArgs(Ag,$resolved(.List)))


//primitive actions

syntax Id ::=
              "add_header"      [token]
            | "copy_header"     [token]
            | "remove_header"   [token]

syntax Bool ::= "#is_header_op" "(" Id ")" [function]
rule #is_header_op(A:Id) => A ==K add_header orBool A ==K remove_header orBool A ==K copy_header

//rule (.K => H) ~> @call(A:Id, $resolved(ListItem(H:HeaderRef) _:List)) when #is_header_op(A)
//rule (H:ResolvedHeaderRef => .K) ~> @call(A:Id, $resolved(ListItem(_:HeaderRef => H) _:List)) when #is_header_op(A)

rule <k> @call(add_header, $resolved(ListItem($href(I:InstanceName)))) => #if V #then .K #else @initInstance(I) #fi ... </k>
     <instances> <instance> <i-name> I </i-name> <metadata> false </metadata> <typeName> T:HeaderTypeName </typeName> <valid> V:Bool => true </valid> ... </instance> ... </instances>
     <headers> <header> <h-name> T </h-name> <h-fields> _:FieldDecs </h-fields> ... </header> ... </headers>
     when notBool #is_array_element(I)
//TODO: currently it can not handle headers with variable length field
//rule @call(add_header, $resolved(ListItem($href($element(I:InstanceName, Idx:Int))))) => //TODO
// assuming the array bound is checked at insertion

rule <k> @call(remove_header, $resolved(ListItem($href(I:InstanceName)))) => @invalidateInstance($href(I)) ... </k>
          when notBool #is_array_element(I)
//rule @call(remove_header, $resolved(ListItem($href($element(I:InstanceName, Idx:Int))))) => //TODO
// assuming the array bound in checked at insertion

syntax KItem ::= "@invalidateInstance" "(" ResolvedHeaderRef ")"
rule <k> @invalidateInstance($href(I:InstanceName)) => .K  ... </k>
     <instances> <instance> <i-name> I </i-name> <metadata> false </metadata> <valid> _ => false </valid> <fieldVals> _:Map => .Map </fieldVals> ... </instance> ... </instances>


//rule (.K => H) ~> @call(copy_header, $resolved(ListItem(_:ResolvedHeaderRef) ListItem(H:HeaderRef)))
//rule (H:ResolvedHeaderRef => .K) ~> @call(copy_header, $resolved(ListItem(_:ResolvedHeaderRef) ListItem(_:HeaderRef => H)))

rule <k> @call(copy_header, $resolved(ListItem($href(D:InstanceName)) ListItem($href(S:InstanceName)))) => .K ... </k>
     <instances>
        <instance> <i-name> S </i-name> <metadata> false </metadata> <typeName> T:HeaderTypeName </typeName> <valid> V:Bool </valid> <fieldVals> FV:Map </fieldVals> ... </instance>
        <instance> <i-name> D </i-name> <metadata> false </metadata> <typeName> T </typeName> <valid> _:Bool => V </valid> <fieldVals> _:Map => FV </fieldVals> ... </instance>
     ...
     </instances>

syntax Id ::=
                "push"        [token]
              | "pop"         [token]

rule <k> @call(push, $resolved(ListItem($aref(I:InstanceName)) ListItem(@val(C:Int,_,_)))) => @shiftElements(I,S -Int C -Int 1,C,-1) ~> @resetElements(I,minInt(C,S) -Int 1,-1) ~> @updateArrayInfo(I)  ... </k>
     <arrays> I |-> $array(S:Int,_:Int,_:Int) _:Map </arrays>
     when C >Int 0
//rule <k> @call(pop, $resolved(ListItem($aref(I:InstanceName)) ListItem(@val(C:Int,_,_)))) => @shiftElements(I,C,(0 -Int C),1) ~> @resetElements(I,maxInt(0,S -Int C),1) ~> @updateArrayInfo(I)  ... </k>
//actually the specification does not mention that the element at the end of the list are reset, they are only invalidated
rule <k> @call(pop, $resolved(ListItem($aref(I:InstanceName)) ListItem(@val(C:Int,_,_)))) => @shiftElements(I,C,(0 -Int C),1) ~> @invalidateElements(I,maxInt(0,S -Int C),1) ~> @updateArrayInfo(I)  ... </k>
     <arrays> I |-> $array(S:Int,_:Int,_:Int) _:Map </arrays>
     when C >Int 0



//syntax IterDirection ::= "$forward" | "$backward"
syntax KItem ::= "@shiftElements" "(" InstanceName "," Int "," Int "," Int ")" //index, shift amount and direction, iteration amount and direction
//Iter forward => shift backward
//Iter backward => shift forward
rule <k> @shiftElements (I:InstanceName, Idx:Int, C:Int, D:Int) =>
        #if Idx <Int 0 orBool Idx >=Int S #then .K #else
            #if (Idx +Int C) <Int 0 orBool (Idx +Int C) >=Int S  #then
                $internal_error
            #else
                @call(copy_header, $resolved(ListItem($href($element(I,Idx +Int C))) ListItem($href($element(I,Idx)))))
                ~> @shiftElements (I, Idx +Int D, C, D)
            #fi
        #fi
     ...
     </k>
     <arrays> I |-> $array(S:Int,_:Int,_:Int) _:Map </arrays>


syntax KItem ::= "@resetElements" "(" InstanceName "," Int "," Int ")" //arrayindex, shift amount and direction
rule <k> @resetElements(I:InstanceName,Idx:Int,D:Int) =>
         #if Idx <Int 0 orBool Idx >=Int S #then
            .K
         #else
            @invalidateInstance($href($element(I,Idx))) ~> @initInstance($element(I,Idx)) ~> @resetElements(I,Idx +Int D,D)
         #fi
     ...
     </k>
     <arrays> I |-> $array(S:Int,_:Int,_:Int) _:Map </arrays>

syntax KItem ::= "@invalidateElements" "(" InstanceName "," Int "," Int ")" //arrayindex, shift amount and direction
rule <k> @invalidateElements(I:InstanceName,Idx:Int,D:Int) =>
         #if Idx <Int 0 orBool Idx >=Int S #then
            .K
         #else
            @invalidateInstance($href($element(I,Idx))) ~> @invalidateElements(I,Idx +Int D,D)
         #fi
     ...
     </k>
     <arrays> I |-> $array(S:Int,_:Int,_:Int) _:Map </arrays>


syntax KItem ::= "@updateArrayInfo" "(" InstanceName ")" //update last,next
rule @updateArrayInfo(I) => @updateLast(I) ~> @updateNext(I)

syntax KItem ::=   "@updateLast" "(" InstanceName ")"
rule <k> @updateLast (I:InstanceName) => @updateLast($element(I,S -Int 1)) ... </k>
     <arrays> I |-> $array(S:Int,_,_) _:Map </arrays>
rule <k> @updateLast($element(I:InstanceName, Idx:Int)) => .K ... </k>
     <instances> <instance> <i-name> $element(I,Idx) </i-name> <valid> true </valid> ... </instance> ... </instances>
     <arrays> I |-> $array(_:Int,_,_:Int => Idx) _:Map </arrays>
rule <k> @updateLast($element(I:InstanceName, Idx:Int => (Idx -Int 1))) ... </k>
     <instances> <instance> <i-name> $element(I,Idx) </i-name> <valid> false </valid> ... </instance> ... </instances>
     when Idx >=Int 0
rule <k> @updateLast($element(I:InstanceName, Idx:Int)) => .K ... </k>
     <arrays> I |-> $array(_:Int,_,_:Int => -1) _:Map </arrays>
     when Idx <Int 0

syntax KItem ::=   "@updateNext" "(" InstanceName ")"
rule <k> @updateNext (I:InstanceName) => @updateNext($element(I,0)) ... </k> when notBool #is_array_element(I)
rule <k> @updateNext($element(I:InstanceName, Idx:Int)) => .K ... </k>
     <instances> <instance> <i-name> $element(I,Idx) </i-name> <valid> false </valid> ... </instance> ... </instances>
     <arrays> I |-> $array(_:Int,_:Int => Idx,_:Int) _:Map </arrays>
rule <k> @updateNext($element(I:InstanceName, Idx:Int => (Idx +Int 1))) ... </k>
     <instances> <instance> <i-name> $element(I,Idx) </i-name> <valid> true </valid> ... </instance> ... </instances>
     <arrays> I |-> $array(S:Int,_,_) _:Map </arrays>
     when Idx <Int S
rule <k> @updateNext($element(I:InstanceName, Idx:Int)) => .K ... </k>
     <arrays> I |-> $array(S:Int,_:Int => S,_:Int) _:Map </arrays>
     when Idx >=Int S


syntax Id ::= "no_op" [token]
rule @call(no_op, $resolved(_)) => .K

//replace multiple rules with check for KLabel (i.e K REFLECTION)
syntax Id ::= "modify_field" [token]
rule @call (modify_field , $resolved(ListItem(D:FieldRef) ListItem(S:FieldRef) Rest:List)) =>
            //@if @isValid(S) @then
                @readField(S) ~> @call(modify_field,$resolved(ListItem(D) ListItem(S) Rest))
            //@else
            //  .

rule (V:Val => .) ~> @call(modify_field , $resolved(ListItem(_) ListItem(_ => V) _:List))
rule @call (modify_field , $resolved(ListItem(D:FieldRef) ListItem(S:Val) ListItem(M:Val))) =>
           //@if @isValid(I.F) @then
                @writeFieldAdjusted(D, (@readField(D) %& (~ M)) %| (S %& M))
           //@else
           //     .

rule @call (modify_field , $resolved(ListItem(D:FieldRef) ListItem(S:Val))) =>
           //@if @isValid(I.F) @then
                @writeFieldAdjusted(D, S)
           //@else
           //    .


syntax Id ::= "subtract_from_field" [token] | "add_to_field" [token]
rule @call (subtract_from_field, $resolved(ListItem(D:FieldRef) ListItem(V:KItem))) =>
          @call (subtract, $resolved(ListItem(D) ListItem(D) ListItem(V)))

rule @call (add_to_field, $resolved(ListItem(D:FieldRef) ListItem(V:KItem))) =>
          @call (add, $resolved(ListItem(D) ListItem(D) ListItem(V)))


syntax Id ::=
                "subtract"      [token]
              | "add"           [token]
              | "bit_and"       [token]
              | "bit_or"        [token]
              | "bit_xor"       [token]
              | "shift_left"    [token]
              | "shift_right"   [token]


syntax Bool ::= "#is_arithmetic" "(" Id ")" [function]
rule #is_arithmetic(A:Id) => A ==K subtract orBool A ==K add orBool A ==K bit_and orBool A ==K bit_or orBool A ==K bit_xor orBool A ==K shift_left orBool A ==K shift_right

/*rule @call (F:Id, $resolved(ListItem(D:FieldRef) ListItem(V1:FieldRef) ListItem(V2))) =>
        //@if @isValid(V1) @then
		    @readField(V1) ~> @call(F,$resolved(ListItem(D) ListItem(V1) ListItem(V2)))
	    //@else
		//    .
		when #is_arithmetic(F)

rule (V:Val => .) ~> @call(F:Id , $resolved(ListItem(_) ListItem(_ => V) _:List)) when #is_arithmetic(F)
rule @call (F:Id, $resolved(ListItem(D:FieldRef) ListItem(V1:Val) ListItem(V2:FieldRef))) =>
         //@if @isValid(V2) @then
                @readField(V2) ~> @call(subtract,$resolved(ListItem(D) ListItem(V1) ListItem(V2)))
         //@else
         //      .
        when (F ==K subtract) orBool (F ==K add)

rule (V:Val => .) ~> @call(F:Id , $resolved(ListItem(_) ListItem(_:Val) ListItem(_ => V))) when (F ==K subtract) orBool (F ==K add) */

//rule @call (F:Id, $resolved(ListItem(D:FieldRef) ListItem(V1) ListItem(V2))) =>
//    @makePair(V1,V2) ~> @call(F,$resolved(ListItem(D) ListItem(V1) ListItem(V2)))
//    when #is_arithmetic(F) wrong: causes loop
rule @call (F:Id, $resolved(ListItem(D:FieldRef) ListItem(V1) ListItem(V2))) =>
    @makePair(V1,V2) ~> @call(F,$resolved(ListItem(D) ListItem(V1:FieldRef) ListItem(V2:KItem)))
    when #is_arithmetic(F)
rule @call (F:Id, $resolved(ListItem(D:FieldRef) ListItem(V1) ListItem(V2))) =>
    @makePair(V1,V2) ~> @call(F,$resolved(ListItem(D) ListItem(V1:KItem) ListItem(V2:FieldRef)))
    when #is_arithmetic(F)
rule ($pair(V1:Val,V2:Val) => .K) ~> @call (F:Id, $resolved(ListItem(_:FieldRef) ListItem(_ => V1) ListItem(_ => V2))) when #is_arithmetic(F)

rule @call (F:Id, $resolved(ListItem(D:FieldRef) ListItem(V1:Val) ListItem(V2:Val))) =>
	#if (F ==K add) #then
	    V1 + V2
	#else #if (F ==K subtract) #then
	    V1 - V2
	#else #if (F ==K bit_and) #then
	    V1 & V2
	#else #if (F ==K bit_or) #then
	    V1 | V2
	#else #if (F ==K bit_xor) #then
	    V1 ^ V2
	#else #if (F ==K shift_left) #then
	    V1 << V2
    #else #if (F ==K shift_right) #then
        V1 >> V2
    #else
        $internal_error
	#fi #fi #fi #fi #fi #fi #fi

	~> @call (modify_field, $resolved(ListItem(D) ListItem(D /* could not use .K */)))
	when #is_arithmetic(F)

// for bit_and,bit_or,bit_xor: Targets may require dest, value1 and value2 to be the same bit width.
// for shift_left,shift_right: value2 must be positive => TODO ISSUE: what if it is not? is the result undefined or something else should happen? how about shift more that width?


syntax Id ::=    "clone_ingress_pkt_to_ingree" [token]
               | "clone_egress_pkt_to_ingress" [token]
               | "clone_ingress_pkt_to_egress" [token]
               | "clone_egress_pkt_to_egress" [token]
               | "recirculate" [token]
               | "resubmit"    [token]


rule @call (resubmit,    $resolved(ListItem(FL:FieldListName))) => @setCrnt("$specialOp","$resbutmit") ~> @createPacketInit(FL;.FieldListEntryItems)
rule @call (recirculate, $resolved(ListItem(FL:FieldListName))) => @setCrnt("$specialOp","$recirculate") ~> @createPacketInit(FL;.FieldListEntryItems)
rule @call (clone_ingress_pkt_to_ingree, $resolved(ListItem(FL:FieldListName))) => @setCrnt("$specialOp","$cii") ~> @createPacketInit(FL;.FieldListEntryItems)
rule @call (clone_egress_pkt_to_ingress, $resolved(ListItem(FL:FieldListName))) => @setCrnt("$specialOp","cei") ~> @createPacketInit(FL;.FieldListEntryItems )
rule @call (clone_ingress_pkt_to_egress, $resolved(ListItem(FL:FieldListName))) => @setCrnt("$specialOp","$cie") ~> @createPacketInit(FL; .FieldListEntryItems)
rule @call (clone_egress_pkt_to_egress, $resolved(ListItem(FL:FieldListName))) => @setCrnt("$specialOp","$cee") ~> @createPacketInit(FL; .FieldListEntryItems)

syntax KItem ::= "@ingressSpecialOperation" | "@egressSpecialOperation"
rule <k> @ingressSpecialOperation => . ... </k>
     <crnt> M:Map </crnt>
when notBool #in_keys("$specialOp",M)
rule <k> @egressSpecialOperation => . ... </k>
     <crnt> M:Map </crnt>
when notBool #in_keys("$specialOp",M)

rule <k> (@ingressSpecialOperation ~> _ ) => @nextPacket </k>
     <crnt> "$specialOp" |-> "$resubmit" _:Map </crnt>
     <in> (.List => ListItem($packet(P,%SPECIAL_OPERATION_PORT,M))) _:List </in>
     <original> P </original>
     <packetInit> M:Map </packetInit>

rule <k> @ingressSpecialOperation => . ...</k>
     <crnt> "$specialOp" |-> "$cii" _:Map </crnt>
     <in> (.List => ListItem($packet(P,%SPECIAL_OPERATION_PORT,M (standard_metadata.instance_type |-> @ingress_clone)))) _:List </in>
     <original> P </original>
     <packetInit> M:Map </packetInit>

rule <k> @ingressSpecialOperation => . ...</k>
     <crnt> "$specialOp" |-> "$cie" _:Map </crnt>
     <in> (.List => ListItem($packet(P,%SPECIAL_OPERATION_PORT,M (standard_metadata.instance_type |-> @egress_clone)))) _:List </in>
     <original> P </original>
     <packetInit> M:Map </packetInit>

rule <k> (@egressSpecialOperation ~> _ ) => @nextPacket </k>
     <crnt> "$specialOp" |-> "$recirculate" _:Map </crnt>
     <in> (.List => ListItem($packet(P,%SPECIAL_OPERATION_PORT,M))) _:List </in>
     <packetout> P </packetout>
     <packetInit> M:Map </packetInit>

rule <k> @egressSpecialOperation => . ...</k>
     <crnt> "$specialOp" |-> "$cei" _:Map </crnt>
     <in> (.List => ListItem($packet(P,%SPECIAL_OPERATION_PORT,M (standard_metadata.instance_type |-> @ingress_clone)))) _:List </in>
     <packetout> P </packetout>
     <packetInit> M:Map </packetInit>

rule <k> @egressSpecialOperation => . ...</k>
     <crnt> "$specialOp" |-> "$cee" _:Map </crnt>
     <in> (.List => ListItem($packet(P,%SPECIAL_OPERATION_PORT,M (standard_metadata.instance_type |-> @egress_clone)))) _:List </in>
     <packetout> P </packetout>
     <packetInit> M:Map </packetInit>
//TODO: directly support cie cee


syntax Val ::= "@ingress_clone" | "@egress_clone"

syntax KItem ::=        "@createPacketInit" "(" FieldListEntryItems ")"

rule @createPacketInit(.FieldListEntryItems) => .
//rule @createPacketInit(V:FieldValue ; Rest:FieldListEntryItems)
rule @createPacketInit(F:FieldRef ; Rest:FieldListEntryItems) => @addPacketInit(F) ~> @createPacketInit(Rest)
rule <k> @createPacketInit(N:FieldListName ; Rest:FieldListEntryItems) => @createPacketInit(E)  ~> @createPacketInit(Rest) ... </k>
     <fieldLists> <fieldList> <fl-name> N </fl-name> <fl-fields> E:FieldListEntryItems </fl-fields> ... </fieldList> ... </fieldLists>
rule <k> @createPacketInit(N:InstanceName ; Rest:FieldListEntryItems) => @createPacketInit(@getFieldsAsFLI(N,F,Rest)) ~> @createPacketInit(Rest) ... </k> //todo: array
     <instances> <instance> <i-name> N </i-name> <typeName> H:HeaderTypeName </typeName> ...   </instance> ... </instances>
     <headers> <header> <h-name> H </h-name> <h-fields> F:FieldDecs </h-fields> ... </header> ... </headers>

syntax KItem ::=    "@addPacketInit" "(" FieldRef")"
rule <k> @addPacketInit( I:InstanceName . F:FieldName ) =>  . </k> //todo: array
     <instances> <instance> <i-name> I </i-name> <metadata> true </metadata> <fieldVals> F |-> V:Val _:Map </fieldVals> ... </instance> ... </instances>
     <packetInit> M:Map => M [(I.F) <- V] </packetInit>



syntax Id ::= "count" [token]
rule <k> @call (count , $resolved(ListItem(C:Id) ListItem(@val(I:Int,_,_)))) => @getStatefulIndexInActionCall(C, I) ~> @updateCounter(C, 0) ... </k>
     <statefuls> <stateful> <s-name> C </s-name> <stype> $counter </stype>  ... </stateful> ... </statefuls>
rule I:Int ~> @updateCounter(C:Id, 0) => @updateCounter(C, I)

syntax Id ::= "execute_meter" [token]
rule <k> @call (execute_meter , $resolved(ListItem(C:Id) ListItem(@val(I:Int,_,_)) ListItem(F:FieldRef))) => @getStatefulIndexInActionCall(C, I) ~> @updateMeter(C, 0, F) ... </k>
     <statefuls> <stateful> <s-name> C </s-name> <stype> $meter </stype>  ... </stateful> ... </statefuls>
rule I:Int ~> @updateMeter(C:Id, 0, F:FieldRef) => @updateMeter(C, I, F)

syntax Id ::= "register_read" [token]
rule <k> @call (register_read , $resolved(ListItem(F:FieldRef) ListItem(C:Id) ListItem(@val(I:Int,_,_)))) => @getStatefulIndexInActionCall(C, I) ~> @writeFieldAdjusted(F, @readStateful(C, 0)) ... </k>
     <statefuls> <stateful> <s-name> C </s-name> <stype> $register </stype>  ... </stateful> ... </statefuls>
rule I:Int ~> @writeFieldAdjusted(F, @readStateful(C, 0)) => @writeFieldAdjusted(F, @readStateful(C, I))

syntax Id ::= "register_write" [token]
rule @call (register_write , $resolved(ListItem(C:Id) ListItem(I:Val) ListItem(F:FieldRef) )) => @readField(F) ~> @call (register_write , $resolved(ListItem(C) ListItem(I) ListItem(F) ))
rule V:Val ~> @call (register_write , $resolved(ListItem(C) ListItem(I) ListItem(_) )) => @call (register_write , $resolved(ListItem(C) ListItem(I) ListItem(V) ))
rule <k> @call (register_write , $resolved(ListItem(C:Id) ListItem(@val(I:Int,_,_)) ListItem(V:Val) )) => @getStatefulIndexInActionCall(C, I) ~> @writeStatefulAdjusted(C, 0, V) ... </k>
     <statefuls> <stateful> <s-name> C </s-name> <stype> $register </stype>  ... </stateful> ... </statefuls>
rule I:Int ~> @writeStatefulAdjusted(C, 0, V) => @writeStatefulAdjusted(C, I, V)

syntax KItem ::= "@getStatefulIndexInActionCall" "(" Id "," Int ")"
rule <k> @getStatefulIndexInActionCall(C:Id, I:Int) => #if (B ==K $direct) #then CR #else I #fi   ... </k>
     <statefuls> <stateful> <s-name> C </s-name> <stype> T:StatefulType </stype> <s-opts> "$binding" |-> B:BindingType M:Map </s-opts> ... </stateful> ... </statefuls>
     <crnt> ("$table" |-> CT:TableName) ("$rule" |-> CR:Int) _:Map </crnt>
     when
        ((B ==K $direct) impliesBool (T =/=K $counter)) andBool
        //((B =/=K $static_global) impliesBool (#in_keys("$table", M) andBool (#castToId(M["$table"]) ==K CT))) andBool //M[$table] evaluates to Bottom it is problematic
        ((B =/=K $static_global) impliesBool #table_matches(M,CT)) andBool
        ((B =/=K $direct) impliesBool (#in_keys("$instant_count", M) andBool (I <Int #get_instant_count(M))))

syntax Int ::= "#get_instant_count" "(" Map ")" [function]
rule #get_instant_count ("$instant_count" |-> I:Int _:Map) => I

syntax Bool ::= "#table_matches" "(" Map "," TableName ")" [function]
rule #table_matches( ("$table" |-> T:TableName) _:Map, CT:TableName) => T ==K CT
rule #table_matches( M:Map, _) => false when notBool #in_keys("$table", M)

syntax Id ::= "drop" [token]

rule @call (drop , $resolved( .List )) => @writeField(standard_metadata, egress_spec, %DROP_PORT)
//TODO: there should be some limitation in using the action which is not currently enforced, check progress.txt

//-------------------action profile-------------------------
syntax KItem ::= "@callOrDeref" "(" ActionCallOrActionProfileRef ")"
rule @callOrDeref(@call(A:ActionName, X)) => @call(A,X) ~> @setCrnt("$action", A)
rule <k> @callOrDeref(@apref(Id:Int)) => @deref(P, Id) ... </k>
     <tables> <table> <t-name> T </t-name> <t-acts> action_profile: P:ActionProfileName  ;</t-acts> ... </table> ... </tables>
     <crnt> ("$table" |-> T:TableName) _:Map </crnt>

syntax KItem ::= "@deref" "(" ActionProfileName "," Int ")"
rule <k> @deref(P:ActionProfileName , Id:Int) => @callOrDeref(C) ... </k>
     <actionProfiles> <actionProfile> <ap-name> P </ap-name> <entries> Id |-> C:ActionCall _:Map </entries> ... </actionProfile> ... </actionProfiles>
rule <k> @deref(P:ActionProfileName , Id:Int) => @calculateFLC(FLC) ~> @deref(P,Id) ... </k>
     <actionProfiles> <actionProfile> <ap-name> P </ap-name> <entries> Id |-> _:List _:Map </entries> <ap-opts> "$selector" |-> S:SelectorName _:Map </ap-opts> ... </actionProfile> ... </actionProfiles>
     <actionSelectors> <actionSelector> <as-name> S </as-name> <key> FLC:FieldListCalculationName </key> ... </actionSelector> ... </actionSelectors>
rule <k> @val(I:Int,_,false) ~> @deref(P:ActionProfileName , Id:Int) => @callOrDeref(#castToActionCall(G[I modInt size(G)])) ... </k>
     <actionProfiles> <actionProfile> <ap-name> P </ap-name> <entries> (Id |-> G:List) _:Map </entries> <ap-opts> "$selector" |-> S:SelectorName _:Map </ap-opts> ... </actionProfile> ... </actionProfiles>
     <actionSelectors> <actionSelector> <as-name> S </as-name> <key> _:FieldListCalculationName </key> ... </actionSelector> ... </actionSelectors>

syntax ActionCall ::= "#castToActionCall" "(" KItem ")" [function]
//rule #castToActionCall(X:ActionCall) => X
rule #castToActionCall(ListItem(X:ActionCall)) => X //workaround for K issue #2343


//-------------------deparsing------------------------------
syntax Id ::= "egress" [token]
rule <k> @egress =>
        //@if @readField(standard_metadata.egress_spec) ==K %DROP_PORT @then  //==K is a function as gets evaluated before @readField
        @if @isDrop @then
            @drop
        @else
            @if @egressDefined(/*<controlFlows>*/ S /*</controlFlows>*/)  @then
                egress(); ~> @if @isDrop @then @drop @else @deparseNext(L) @fi
            @else
                @deparseNext(L)
            @fi
        @fi
     ...
     </k>
     <dporder> L:List </dporder>
//     <controlFlows> S </controlFlows>
     <cfset> S </cfset> //ref: K issue #2279

syntax KItem /*Val*/ ::= "@isDrop"
rule <k> @isDrop => V ==K %DROP_PORT ...  </k>
     <instances> <instance> <i-name> standard_metadata </i-name> <fieldVals> egress_spec |-> V:Val _:Map </fieldVals> ... </instance> ... </instances>

syntax KItem ::= "@addPayload"
rule <k> @addPayload => .K ... </k>
     <packet> Packet:List  </packet>
     <packetout> _:List (.List => range(Packet, I ,0)) </packetout>
     <index> I:Int </index>
     when I <Int size(Packet)
rule <k> @addPayload => .K ... </k>
     <packet> Packet:List  </packet>
     <index> I:Int </index>
     when I >=Int size(Packet)

rule <k> @addPayload => .K ... </k>
     <packet> Packet:String  </packet>
     <packetout> _:List (.List => ListItem(@val(String2Base(substrString(Packet,I,lengthString(Packet)),2), lengthString(Packet) -Int I  ,false))) </packetout>
     <index> I:Int </index>
     when I <Int lengthString(Packet)
rule <k> @addPayload => .K ... </k>
     <packet> Packet:String  </packet>
     <index> I:Int </index>
     when I >=Int lengthString(Packet)

syntax Bool ::= "@egressDefined" "(" Set ")" [function]
rule @egressDefined(S) => notBool notBool (egress in S) //workaround to get rid of ambiguities

//syntax Bool ::= "@egressDefined" "(" K ")" [function]
//rule @egressDefined(<controlFlows> <control> <name> F:ControlFunctionName </name> ... </control> Rest </controlFlows>) =>
//	#if F ==K egress #then true #else @egressDefined(<controlFlows> Rest </controlFlows> #fi
//rule @egressDefined(<controlFlows> .Bag </controlFlows>) => false

syntax KItem ::= "@deparseNext" "(" List ")"
rule @deparseNext(ListItem(H:InstanceName) Rest:List) => @deparseHeader(H) ~> @deparseNext(Rest) [structural]
rule @deparseNext(.List) => @addPayload

syntax KItem ::= "@deparseHeader" "(" InstanceName ")"
rule <k> @deparseHeader(I:InstanceName) => #if M ==Bool false #then .K #else @deparseFields(I,F) #fi ...</k>
        <instances>
            <instance> <i-name> I </i-name> <typeName> H:HeaderTypeName </typeName> <valid> M:Bool </valid>  ... </instance>
            ...
        </instances>
        <headers>
            <header> <h-name> H </h-name> <h-fields> F:FieldDecs </h-fields>  ... </header>
            ...
        </headers>
rule <k> @deparseHeader(I:InstanceName) => @deparseArray(I,S -Int 1) ... </k>
     <arrays> I |-> $array(S,_,_) _:Map </arrays>

syntax KItem ::= "@deparseArray" "(" InstanceName "," Int ")"
rule @deparseArray(I,0) => @deparseHeader($element(I,0))    [structural]
rule @deparseArray(I,Idx) => @deparseArray(I, Idx -Int 1) ~> @deparseHeader($element(I,Idx)) when Idx >Int 0 [structural]

syntax KItem ::= "@deparseFields" "(" InstanceName "," FieldDecs ")"
rule @deparseFields(I:InstanceName,F:FieldName : _:ConstValue ( _:FieldMods ) ; Rest:FieldDecs) =>
        @deparseField(I,F) ~> @deparseFields(I,Rest)        [structural]
rule @deparseFields(I:InstanceName,F:FieldName : * ( _:FieldMods ) ; Rest:FieldDecs) =>
        @deparseField(I,F) ~> @deparseFields(I,Rest)        [structural]
rule @deparseFields(_:InstanceName,.FieldDecs) => .        [structural]


syntax KItem ::= "@deparseField" "(" InstanceName "," FieldName ")"
rule <k> @deparseField(I:InstanceName,F:FieldName) => @packetOut(V /*@FieldVal2String(V,@getAttr(F,Fs))*/) ...</k>
         <instances>
             <instance> <i-name> I </i-name> <typeName> _:HeaderTypeName </typeName> <fieldVals> F |-> V:Val ...</fieldVals> ... </instance>
             ...
         </instances>
         <calcFieldSet> CF:Set </calcFieldSet>
         when notBool (I.F in CF)
//         <headers>
//            <header> <name> H </name> <fields> Fs:FieldDecs </fields> ... </header>
//            ...
//         </headers>

rule <k> @deparseField(I:InstanceName,F:FieldName) => @packetOut(@adjustVal(@getAttr(F,Fs),@updateCalcField(I.F,U,V))) ...</k>
     <instances>
          <instance> <i-name> I </i-name> <typeName> H:HeaderTypeName </typeName> <fieldVals> F |-> V:Val ...</fieldVals> ... </instance>
          ...
      </instances>
      <headers>
          <header> <h-name> H </h-name> <h-fields> Fs:FieldDecs </h-fields> ... </header>
         ...
      </headers>
      <calcFields> <calcField> <fieldRef> I . F </fieldRef> <updates> U:List </updates> ... </calcField> ... </calcFields>

//syntax KResult ::= String
//syntax KItem ::= "@packetOut" "(" K /* String */ ")" [strict]
//rule <k> @packetOut(S:String) => . ... </k>
//     <packetout> P:String => P +String S </packetout>
syntax KItem ::= "@packetOut" "(" KItem /* Val */ ")" [strict]
rule <k> @packetOut(V:Val) => . ... </k>
       <packetout> _:List (.List => ListItem(V)) </packetout>



//syntax KItem ::= "@FieldVal2String" "(" K /* Val */ "," FieldDec ")" [strict(1)]
//rule @FieldVal2String(@val(I,_,_), _:FieldName : W:UnsignedValue ( .FieldMods );)  =>
//    @addPadding(Base2String(I,2),USgnVal2Int(W) -Int lengthString(Base2String(I,2)) ,"0")
//TODO: complete this

//syntax String ::= "@addPadding" "(" String "," Int "," String ")" [function] /* String , width , char */
//rule @addPadding(S,0,_) => S
//rule @addPadding(S,I,C) => C +String @addPadding(S,I -Int 1,C) when I >Int 0



//----------------header and field ref--------------------
//syntax HRef ::= "@href" "(" InstanceName ")"
//syntax FieldRef ::= HRef "." FieldName
//syntax KResult ::= HRef
//
//rule HI:InstanceName => @href(HI)
//TODO: support array
//TODO:maybe @href is not needed, instance name is enough



//-----------------array-----------------------------

syntax ArrayInfo ::= "$array" "(" Int "," Int "," Int ")" //size, next, last
syntax InstanceName ::= "$element" "(" InstanceName "," Int ")"

syntax Bool ::= "#is_array_element" "(" InstanceName ")" [function]
rule #is_array_element(_:Id) => false
rule #is_array_element($element(_,_)) => true
//------------------utils-------------------------------
syntax Int ::= "Val2Int" "(" Val ")" [function]
rule Val2Int ( @val(I:Int,_,_) ) => I



syntax Int ::= "USgnVal2Int" "(" ConstValue ")" [function]
//TODO: change all letters to lower case
rule USgnVal2Int( UV:BinaryValueToken ) => String2Base(replaceFirst(replaceAll(BinaryValueToken2String(UV),"_",""),"0b",""),2)
rule USgnVal2Int( UV:DecimalValueToken ) => String2Int(replaceAll(DecimalValueToken2String(UV),"_",""))
rule USgnVal2Int( UV:HexadecimalValueToken ) => String2Base(replaceFirst(replaceAll(HexadecimalValueToken2String(UV),"_",""),"0x",""),16)

syntax String ::= DecimalValueToken2String      ( DecimalValueToken     )    [function, functional, hook(STRING.token2string)]
syntax String ::= BinaryValueToken2String       ( BinaryValueToken      )    [function, functional, hook(STRING.token2string)]
syntax String ::= HexadecimalValueToken2String  ( HexadecimalValueToken )    [function, functional, hook(STRING.token2string)]

syntax KItem ::= "@if" KItem /* Bool */ "@then" K "@else" K "@fi"[strict(1)]
syntax KResult ::= Bool
rule @if true @then T:K @else _:K @fi => T  [transition]
rule @if false @then _:K @else F:K @fi => F [transition]


syntax KItem /* Val */ ::= "@concat" "(" KItem /* Vals */ ")" [strict]

rule @concat(@cons(V:Val,@nil)) => V
rule @concat(@cons(@val(V1:Int,W1:Int,S1:Bool),@cons(@val(V2:Int,W2:Int,S2:Bool), Rest:Vals))) => @concat(@cons(@val((@intrepretUnsigned(@val(V1,W1,S1)) <<Int W2) +Int @intrepretUnsigned(@val(V2,W2,S2))   ,W1 +Int W2,false),Rest))



syntax Int ::= "@intrepretUnsigned" "(" Val ")" [function]
rule @intrepretUnsigned(@val(V:Int,_,false)) => V
//rule @intrepretUnsigned(@val(V:Int,W:Int,true)) => V //TODO

//TODO:temporary, maybe we want to resolve the referece to header first
//If not, complete it is for array
syntax KItem /* Val */ ::=     "@readField" "(" FieldRef  ")"
                             | "@readField" "(" KItem /* ResolvedHeaderRef */ "," FieldName ")" [strict(1)]
rule @readField(H:HeaderRef . F:FieldName) => @readField(H, F)
rule <k> @readField($href(H:InstanceName) , F:FieldName) => V ... </k>
      <instances>
         <instance> <i-name> H </i-name> <valid> true </valid> <fieldVals> (F |-> V:Val) _:Map </fieldVals> ...  </instance> ...
      </instances>

//new in version 1.0.4
rule <k> @readField($href(H:InstanceName) , _:FieldName) => @undef ... </k>
      <instances>
         <instance> <i-name> H </i-name> <valid> false </valid>  ...  </instance> ...
      </instances>

syntax ResolvedHeaderRef ::= "$href" "(" InstanceName ")" | "$aref" "(" InstanceName ")"

/*rule <k> ScalarRef(I:InstanceName) => $href(I) ... </k>
     <instances> <instance> <name> I </name> ... </instance> ... </instances>

rule <k> ArrayRef(I:InstanceName,Idx:UnsignedValue) => $href($element(I,USgnVal2Int(Idx))) ... </k> //TODO (minor): Idx should be ConstValue
     <arrays> I |-> $array(S:Int,_,_) _:Map </arrays> when USgnVal2Int(Idx) <Int S //TODO: what to do for out of bound access

rule <k> ArrayRef(I:InstanceName,last) => $href($element(I,L)) ... </k>
     <arrays> I |-> $array(_:Int,_:Int,L:Int) _:Map </arrays> when L =/=Int -1*/
// Some weired bug in K

rule <k> I:InstanceName => $href(I) ... </k>
     <instances> <instance> <i-name> I </i-name> ... </instance> ... </instances>
rule <k> (I:InstanceName => $aref(I)) ~> @resolveArgs(_,_) ... </k> // if ~> @resolveArgs is not present, it will clash with Id ~> setCrntRule (...)
     <arrays> I |-> _:ArrayInfo _:Map </arrays>
rule <k> I:InstanceName [Idx:UnsignedValue] => $href($element(I,USgnVal2Int(Idx))) ... </k> //TODO (minor): Idx should be ConstValue

     <arrays> I |-> $array(S:Int,_:Int,_:Int) _:Map </arrays>
     when USgnVal2Int(Idx) <Int S
rule <k> I:InstanceName [last] => $href($element(I,L)) ... </k>
     <arrays> I |-> $array(_:Int,_:Int,L:Int) _:Map </arrays>
     when L =/=Int -1

syntax KResult ::= ResolvedHeaderRef

//TODO: same as above
syntax KItem /* Bool */ ::=   "@isValid" "(" KItem /* FieldRef or HeaderRef */ ")"
                            | "@isValidHeader" "(" KItem /*ResolvedHeaderRef*/ ")" [strict,strict]
rule @isValid(H:HeaderRef . _:FieldName) => @isValidHeader(H)
rule @isValid(H:HeaderRef) => @isValidHeader(H)
rule <k> @isValidHeader($href(H:InstanceName)) => V ... </k>
      <instances>
         <instance> <i-name> H </i-name> <valid> V:Bool </valid>  ...  </instance> ...
      </instances>




syntax KItem /* Val */ ::= "@applyMask" "(" KItem /* Val */ "," KItem /* Val */ ")" [strict]
rule @applyMask(V1:Val,V2:Val) => V1 & V2
//TODO ISSUE: is this it?

syntax KItem ::=   KItem "%==" KItem [seqstrict]
                 | KItem "%&&" KItem [seqstrict]
                 | KItem "%&"  KItem [seqstrict]
                 | KItem "%+" KItem [seqstrict]
                 | KItem "%>" KItem [seqstrict]
                 | KItem "%-" KItem [seqstrict]
                 | KItem "%*" KItem [seqstrict]
                 | KItem "%>>" KItem [seqstrict]
                 | KItem "%<<" KItem [seqstrict]
                 | KItem "%<=" KItem [seqstrict]
		         | KItem "%|"  KItem [seqstrict]

rule V1:Val %== V2:Val => V1 == V2
rule V1:Val %& V2:Val => V1 & V2
rule V1:Val %| V2:Val => V1 | V2
rule V1:Val %+ V2:Val => V1 + V2
rule V1:Val %- V2:Val => V1 - V2
rule V1:Val %* V2:Val => V1 * V2
rule V1:Val %>> V2:Val => V1 >> V2
rule V1:Val %<< V2:Val => V1 << V2
rule V1:Val %> V2:Val => V1 > V2
rule V1:Val %<= V2:Val => V1 <= V2
rule B1:Bool %&& B2:Bool => B1 andBool B2


syntax KItem /* KResult */ ::= "@makePair" "(" KItem /* Val */ "," KItem /* Val */ ")" [seqstrict]
rule @makePair(V1:Val,V2:Val) => $pair(V1,V2)

//------------------const value--------------------------



syntax Vals ::= "@nil" | "@cons" "(" Val "," Vals ")"
syntax KResult ::= Val | Vals

syntax KItem /* Vals */ ::= "@makeCons" "(" KItem /* Val */ "," KItem /* Vals */ ")" [seqstrict]

rule @makeCons(V:Val,Vs:Vals) => @cons (V,Vs)

syntax KItem /* Vals */ ::= "@makeConcat" "(" KItem /* Vals */ "," KItem /* Vals */ ")" [seqstrict]
rule @makeConcat(@nil, Vs:Vals) => Vs
rule @makeConcat(@cons(V:Val,Rest:Vals), Vs:Vals) => @makeCons(V,@makeConcat(Rest,Vs))


rule UV::UnsignedValue => @val(USgnVal2Int(UV),0,false)
rule + UV:UnsignedValue => UV
rule nconstv(UV:UnsignedValue) => @negative(UV)
rule (W:DecimalValueToken' UV:UnsignedValue) => @setWidth(USgnVal2Int(W),UV)
rule (+ W:WidthSpec UV:UnsignedValue) => W UV
rule nwconstv(W:WidthSpec,UV:UnsignedValue) => @negative(W UV)

syntax KItem ::= "@negative" "(" KItem ")" [strict]
rule @negative(@val(I:Int,W:Int,S:Bool)) => #if (notBool S) andBool (W ==Int 0) #then @val(0 -Int I,0,true) #else @val(0 -Int I,W +Int 1,true) #fi

syntax KItem ::= "@setWidth" "(" KItem "," KItem ")" [seqstrict]
rule @setWidth(@val(W:Int,0,false),@val(I:Int,0,false)) => @val(I,W,false) when I <Int (2 ^Int W)
//TODO ISSUE: what happens if the unsigned value constant does not fit into the width specified


//----------------------------casts-------------------------------------------
syntax FieldRef ::= "#castToFieldRef" "(" KItem ")" [function]
rule #castToFieldRef(X:FieldRef) => X


//----------------------------temporary utils----------------------------------


syntax KItem ::= "$pause" | "$compile_error" | "$internal_error"


endmodule
