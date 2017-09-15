require "configuration.k"
require "initialization.k"


module P4-SEMANTICS
imports P4-COMMON
imports CONFIGURATION
imports INITIALIZATION

//macros




//---------------- putting decralarions into configuration cells--------------------------------

syntax KItem ::=
          "@processDec" "(" K ")"

rule <k> (Dec:P4Declaration Rest:P4Declarations) => @processDec(Dec) ~> Rest ... </k>

rule <k> (.P4Declarations => .) ... </k>

// @processDec


// header dec
rule <k> @processDec(header_type Name:HeaderTypeName { fields { Fields:FieldDecs } Opts:HeaderOptionals }) => . ... </k>
    <headers>  (.Bag =>
        <header>  <name> Name </name> <opts> @processHeaderOpts(Opts, .Map) @sumofFixedWidthBits(Fields, 0) </opts> <fields> Fields </fields>  </header>)
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
         (.Bag => <fieldList> <name> Name </name> <fields> FL </fields> ... </fieldList>
         ) ...
     </fieldLists>


// field_list_calculation dec
rule <k> @processDec(field_list_calculation Name:FieldListCalculationName { input { FLs:FieldListNameItems }  algorithm : A:StreamFunctionAlgorithmName ; output_width : W:UnsignedValue ; } ) => . ... </k> //TODO(minor): W should be ConstValue
     <fieldListCalcs>
        (.Bag => <fieldListCalc> <name> Name </name> <fLists> @FLAsList(FLs, .List) </fLists> <algorithm> A </algorithm> <outWidth> USgnVal2Int(W) </outWidth> ... </fieldListCalc>
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

rule <k> @processDec(metadata Type:HeaderTypeName Name:InstanceName { Asgn:FieldValueAssignments } ) => @initFields(Name,Asgn,@getFieldsSet(Fields,.Set)) ... </k>
    <instances>  (.Bag =>
        <instance>
             <valid> true </valid>
                <metadata> true </metadata> <typeName> Type </typeName> <name> Name </name> <fieldVals> .Map </fieldVals>  ...
        </instance>
    ) ... </instances>
    <headers>  <header>  <name> Type </name>  <fields> Fields:FieldDecs </fields> ... </header> ... </headers>


rule <k> @processDec(header Type:HeaderTypeName Name:InstanceName ; ) => . ... </k>
    <instances> (.Bag =>
        <instance>
             <valid> false </valid> <metadata> false </metadata> <typeName> Type </typeName> <name> Name </name>  ...
        </instance>
    ) ... </instances>
//rule <k> @processDec(header Type:HeaderTypeName Name:InstanceName [ Size:ConstValue ] ; ) => . ... </k>
//    <instances> ... (.Bag =>
//        <instance>
//            ... <valid> false </valid> <metadata> false </metadata> <typeName> Type </typeName> <name> Name </name> <arraysize> Size </arraysize>   ...
//        </instance>
//    ) ... </instances>
//TODO: array is not supported yet

syntax Set ::= "@getFieldsSet" "(" FieldDecs "," Set ")" [function]
rule @getFieldsSet(N:FieldName : _:BitWidth ( _:FieldMods ) ; Rest:FieldDecs, Acc:Set) => @getFieldsSet(Rest, SetItem(N) Acc)
rule @getFieldsSet(.FieldDecs, Acc:Set) => Acc
//TODO: check a field is not decrlared twice


syntax Map ::= "@initFields" "(" InstanceName "," FieldValueAssignments "," Set ")"
rule @initFields(I, .FieldValueAssignments, .Set) => .
rule @initFields(I, .FieldValueAssignments, SetItem(F:FieldName) Rest:Set) =>
        @initField(I,F,@val(0,0,false)) ~> @initFields(I, .FieldValueAssignments, Rest)
rule @initFields(I, F:FieldName : V:FieldValue ; ARest:FieldValueAssignments, SetItem(F:FieldName) FRest:Set) =>
        @initField(I,F,V) ~> @initFields(I, ARest, FRest)

syntax Map ::= "@initField" "(" InstanceName "," FieldName "," K /* Val */ ")" [strict(3)]
rule <k> @initField(N,F,V:Val) => . ...</k>
        <instances>
            <instance> <name> N </name>  <fieldVals> (.Map => F |-> V) _:Map </fieldVals>  ... </instance>
            ...
        </instances>

//parser

rule <k> @processDec(parser Name:ParserStateName { Body:ParserFunctionBody }) => . ... </k>
    <parserStates> (.Bag =>
          <state>
            <name> Name </name> <body> Body </body> ...
          </state>
    ) ... </parserStates>


// stateful
   syntax StatefulType ::= "$counter" | "$meter" | "$register"
   syntax BindingType ::= "$direct" | "$static" | "$static_global"

rule <k> @processDec(counter Name:Id { type : T:CounterType ; SOpt:StatefulOptionals COpt:CounterOptionals }) => @addTableDirect(Name) ... </k>
     <statefuls>
        (.Bag =>
            <stateful>
                <stype> $counter </stype>
                <name> Name </name>
                <opts> ("$counter_type" |-> T) @processStatefulOpts(SOpt, ("$binding" |-> $static_global)) @processCounterOpts(COpt, ("$signed" |-> false) ("$saturating" |-> false)) </opts>
                <width> 0 </width> // = inf
                ...
            </stateful>
        ) ...
     </statefuls>

rule <k> @processDec(meter Name:Id { type : T:MeterType ; MOpt:MeterOptionals SOpt:StatefulOptionals }) =>  @addTableDirect(Name) ... </k>
     <statefuls>
        (.Bag =>
            <stateful>
                <stype> $meter </stype>
                <name> Name </name>
                <opts> ("$meter_type" |-> T) @processStatefulOpts(SOpt, ("$binding" |-> $static_global)) @processMeterOpts(MOpt, ("$signed" |-> false) ("$saturating" |-> false)) </opts>
                <width> 2 </width>
                ...
            </stateful>
        ) ...
     </statefuls>

rule <k> @processDec(register Name:Id { width : W:UnsignedValue ; SOpt:StatefulOptionals ROpt:RegisterOptionals }) => . ... </k>     //TODO(minor): W should be ConstValue
     <statefuls>
        (.Bag =>
            <stateful>
                <stype> $register </stype>
                <name> Name </name>
                <opts> @processStatefulOpts(SOpt, ("$binding" |-> $static_global)) @processRegisterOpts(ROpt, ("$signed" |-> false) ("$saturating" |-> false)) </opts>
                <width> USgnVal2Int(W) </width>
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
     <statefuls> <stateful> <name> N </name> <opts> "$binding" |-> $direct "$table" |-> T:TableName _:Map </opts> ... </stateful> ... </statefuls>
     <tableDirects> T |-> ((.Set => SetItem(N)) _:Set) _:Map </tableDirects>

rule <k> @addTableDirect(N:Id) => . ...</k>
     <statefuls> <stateful> <name> N </name> <opts> "$binding" |-> $direct "$table" |-> T:TableName _:Map </opts> ... </stateful> ... </statefuls>
     <tableDirects> (.Map => (T |-> SetItem(N))) Rest:Map</tableDirects>
     when notBool #in_keys(T, Rest)

rule <k> @addTableDirect(N:Id) => . ...</k>
     <statefuls> <stateful> <name> N </name> <opts> "$binding" |-> B:BindingType _:Map</opts> ... </stateful> ... </statefuls>
     when B =/=K $direct


// syntax KItem ::= "@initStateful" "(" Id ")"
// init on first use

//action

rule <k> @processDec(action Name:ActionName ( Params:ParamList ) { Body:ActionStatements }  ) => . ... </k>
    <actions> (.Bag =>
          <action>
            <name> Name </name> <params> Params </params> <body> Body </body> ...
          </action>
    ) ... </actions>


// action profile
rule <k> @processDec(action_profile Name:ActionProfileName { Act:ActionSpecification Opt:ActionsProfileOptionals } ) => . ... </k>
     <actionProfiles>
        ( .Bag =>
            <actionProfile>
                <name> Name </name>
                <acts> Act </acts>
                <opts> @processActionProfileOptionals(Opt, .Map) </opts>
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
        ( .Bag => <actionSelector> <name> Name </name> <key> FLC </key> ... </actionSelector>) ...
     </actionSelectors>

// table

rule table N:TableName { A:TableActions O:TableOptionals } => table N { reads { .FieldMatchs } A O } [macro]

rule <k> @processDec(table Name:TableName { reads { FM:FieldMatchs }  Act:TableActions Opt:TableOptionals } ) => . ... </k>
         <tables>... (.Bag =>
               <table>
                 <name> Name </name> <reads> FM </reads> <acts> Act </acts> <opts> Opt </opts> <rules> .List </rules> ...
               </table>
         ) ... </tables>


// control

rule <k> @processDec(control Name:ControlFunctionName { Body:ControlStatements } ) => . ... </k>
         <controlFlows> (.Bag =>
               <control>
                    <name> Name </name> <body> Body </body> ...
               </control>
         ) ...  </controlFlows>
	<cfset> (.Set => SetItem(Name)) _ </cfset> //TODO: //TODO: temporary fix for K issue #2279

//--------------------deparse order--------------------------

//find parse order
//syntax KItem ::=  "@parseOrder" "(" K "," K ")" // current, previous
//
//rule <k> @parseOrder(P:K,C:ParserStateName) => @parseOrder(P:K,B) ... </k>
//     <parserStates>
//        <state> <name> C </name> <body> B:ParserFunctionBody   </body> </state>
//        ...
//     </parserStates>
//
//rule @parseOrder(P:K, S:SetStatement Rest:ExtractOrSetStatements Ret:ReturnStatement) => @parseOrder(P,Rest Ret)
//rule <k> @parseOrder(.K, extract(H:HeaderExtractRef); Rest:ExtractOrSetStatements Ret:ReturnStatement) =>  @parseOrder(H,Rest Ret) ...</k>
//     <start> .K => H </start>
//rule <k> @parseOrder(P:HeaderExtractRef, extract(H:HeaderExtractRef); Rest:ExtractOrSetStatements Ret:ReturnStatement) =>  @parseOrder(H,Rest Ret) ...</k>
//     <order> (. => P |-> SetItem(H)) M:Map </order> when notBool P in keys(M)
//rule <k> @parseOrder(P:HeaderExtractRef, extract(H:HeaderExtractRef); Rest:ExtractOrSetStatements Ret:ReturnStatement) =>  @parseOrder(H,Rest Ret) ...</k>
//     <order> (P |-> ((. => SetItem(H)) S:Set)) M:Map </order>
////TODO: more compact if possible
//rule @parseOrder(P:K, .ExtractOrSetStatements Ret:ReturnStatement) =>  @parseOrder(P,Ret)
//rule <k> @parseOrder(P:K, return S:ParserStateName;) =>  @parseOrder(P,S) ... </k>
//      <parserStates>
//         <state> <name> S  </name> ... </state>
//         ...
//      </parserStates>
//rule <k> @parseOrder(P:K, return C:ControlFunctionName;) => . ... </k>
//      <controlFlows>
//            <control> <name> C </name> ... </control>
//            ...
//      </controlFlows>
//rule @parseOrder(P:K, return select ( _ ) { C:CaseEntries } ) =>  @parseOrder(P,C)
//rule @parseOrder(P:K, .CaseEntries) =>  .K
//rule @parseOrder(P:K, _:ValueList : C:CaseReturnValueType ; Rest:CaseEntries) =>
//        @parseOrder(P,Rest) ~> @parseOrder(P,@caseReturnToReturn(C))

//TODO: assuming it is a dag
//TODO: assuming no header stacks

rule <k> @parseOrder(C:ParserStateName) => @parseOrder(B) ... </k>
     <parserStates>
        <state> <name> C </name> <body> B:ParserFunctionBody   </body> </state>
        ...
     </parserStates>
rule @parseOrder(S:SetStatement Rest:ExtractOrSetStatements Ret:ReturnStatement) => @parseOrder(Rest Ret)
rule <k> @parseOrder(extract(H:HeaderExtractRef); Rest:ExtractOrSetStatements Ret:ReturnStatement) =>
            @parseOrder(Rest Ret) ~> @push(H) ...</k>
     <marked> (. => SetItem(H)) S:Set </marked> when notBool H in S
rule <k> @parseOrder(extract(H:HeaderExtractRef); Rest:ExtractOrSetStatements Ret:ReturnStatement) =>  @parseOrder(Rest Ret) ...</k>
     <marked> S:Set </marked> when H in S
//TODO: more compact if possible
rule @parseOrder(.ExtractOrSetStatements Ret:ReturnStatement) =>  @parseOrder(Ret)
rule <k> @parseOrder(return S:ParserStateName;) =>  @parseOrder(S) ... </k>
      <parserStates>
         <state> <name> S  </name> ... </state>
         ...
      </parserStates>
rule <k> @parseOrder(return C:ControlFunctionName;) => . ... </k>
      <controlFlows>
            <control> <name> C </name> ... </control>
            ...
      </controlFlows>
rule @parseOrder(return select ( _ ) { C:CaseEntries } ) =>  @parseOrder(C)
rule @parseOrder(.CaseEntries) =>  .K
rule @parseOrder(_:ValueList : C:CaseReturnValueType ; Rest:CaseEntries) =>
         @parseOrder(@caseReturnToReturn(C)) ~> @parseOrder(Rest) //dfs

syntax KItem ::= "@push" "(" HeaderExtractRef ")"
rule <k> @push(H:HeaderExtractRef) => . ... </k>
     <dporder> (.List => ListItem (H)) ...  </dporder>


// --------------------init------------------------------------

// moved to initialization.k
rule  @exec => @nextPacket

// ------------------------packet to/from buffer-----------------------------

syntax KItem ::= "@nextPacket"
syntax Id ::= "standard_metadata" [token]
rule <k> @nextPacket => @parse&ingress ~> @egress ~> @txenPacket ~> @nextPacket ... </k>
     <buffer> <in> (ListItem($packet(P:List, Port:Int)) => .List) _:List </in> ... </buffer>
     <packet> _ => P </packet>
     <instances>
        <instance>
            <name> standard_metadata </name>
            <fieldVals> _:Map => (String2Id("ingress_port") |-> @val(Port,32,false) String2Id("egress_spec") |-> @undef) </fieldVals>
            ...
        </instance>
        ...
    </instances>
    <parser> <packetSize> .K => @calculatePacketSize(P , 0) </packetSize> ... </parser>


syntax Val ::= "@calculatePacketSize" "(" List "," Int ")" [function]
rule @calculatePacketSize(.List, I:Int) => @val(I /Int 8, 0, false)
rule @calculatePacketSize(ListItem(@val(_,W:Int,_)) Rest:List, I:Int) => @calculatePacketSize(Rest, I +Int W)

//TODO: IMPORTANT: instances must be reset

syntax KItem ::= "@txenPacket"
syntax Id ::= "egress_spec" [token]
rule <k> @txenPacket => . ... </k>
     <packetout> P:List => .List </packetout>
     <buffer> <out>   _:List (.List => ListItem($packet(P,Port))) </out> ... </buffer>
      <instances>
          <instance>
              <name> standard_metadata </name>
              <fieldVals>  egress_spec |-> @val(Port:Int,_,_) ... </fieldVals>
              ...
          </instance>
          ...
      </instances>
//TODO: check if needs to be dropped


//--------------------parsing------------------------------
syntax KItem ::= "@parse&ingress" | "@egress"
rule <k> @parse&ingress => Body  ... </k>
     <parserStates> <state>  <name> start </name> <body> Body </body> ... </state> ...</parserStates>
     <lastExt> _ => .K </lastExt>

rule ESs:ExtractOrSetStatements R:ReturnStatement => ESs ~> R           [structural]
rule ES:ExtractOrSetStatement ESs:ExtractOrSetStatements => ES ~> ESs   [structural]

rule .ExtractOrSetStatements => .

//return to state
//TODO: check it is not control function name
rule <k> return State:ParserStateName ; => Body ... </k>
     <parserStates> <state>  <name> State </name> <body> Body </body> ... </state> ...</parserStates>
     <lastExt> _ => .K </lastExt>

//return to control function
rule <k> return Control:ControlFunctionName ; => @verifyCalcFields ~> Control(); ... </k>
    <controlFlows> <control> <name> Control </name> ... </control> ... </controlFlows>


//return parser_exception
//TODO

//return select

rule return select ( SE:SelectExp ) { CE:CaseEntries} => @select(@readFDRefs(SE),CE)

syntax KItem ::= "@select" "(" K /* Vals */ "," CaseEntries ")" [strict(1)]
rule @select (Vs:Vals,  VM:ValueOrMaskeds : CA:CaseReturnValueType; Rest:CaseEntries )
    => @selectCheckCase(Vs, @VMstoVals(VM), CA, Rest)
rule @select (_:Vals, default : CA:CaseReturnValueType; _:CaseEntries) => @caseReturnToReturn(CA)

syntax KItem ::= "@selectCheckCase" "(" Vals "," K /* Vals */ "," CaseReturnValueType "," CaseEntries  ")" [strict(2)]
rule @selectCheckCase(Vs:Vals, Vss:Vals, CA:CaseReturnValueType, Rest:CaseEntries)
    => @if @concat(Vs) %== @concat(Vss)  @then @caseReturnToReturn(CA) @else @select(Vs,Rest)  //TODO: change this to == in Val when we have complete semantics for it

syntax KItem /* Vals */ ::= "@VMstoVals" "(" ValueOrMaskeds ")"
rule @VMstoVals (.ValueOrMaskeds) => @nil
rule @VMstoVals (VM:ValueOrMasked , Rest:ValueOrMaskeds) => @makeCons(VM,@VMstoVals(Rest))

syntax ReturnValueType ::= "@caseReturnToReturn" "(" CaseReturnValueType ")" [function]
rule @caseReturnToReturn(PS:ParserStateName) => return PS ;
rule @caseReturnToReturn(CF:ControlFunctionName) => return CF ;
rule @caseReturnToReturn(parse_error PE:ParserExceptionName) => parse_error PE ;

//TODO: rule V:Val mask M:Val => ?
//TODO: rule VS:ValueSetName => ?



syntax KItem /* Vals */ ::= "@readFDRefs" "(" SelectExp ")"
rule @readFDRefs(.FieldOrDataRefs) => @nil
rule @readFDRefs(F:FieldRef , Rest:FieldOrDataRefs) => @makeCons(@readField(F),@readFDRefs(Rest))
rule <k> @readFDRefs(latest . FN:FieldName , Rest:FieldOrDataRefs) =>  @makeCons(@readField(H.FN),@readFDRefs(Rest)) ... </k>
        <lastExt> H:InstanceName </lastExt>
//TODO rule @readVals(current())




//extract
rule <k> extract (Name:InstanceName) ;  => @extract(Name,Fields) ... </k>
     <instances>
        <instance> <name> Name </name> <metadata> false </metadata> <typeName> Type:HeaderTypeName </typeName> ... </instance> ...
     </instances>
     <headers>
        <header> <name> Type </name>  <fields> Fields:FieldDecs </fields> ... </header> ...
     </headers>
//TODO ISSUE: what happens if a valid header gets extracted again?

syntax KItem ::= "@extract" "(" InstanceName "," FieldDecs ")"
rule <k> @extract(N:InstanceName, .FieldDecs) => . ... </k>
     <instances>
            <instance> <name> N </name>  <valid> false => true </valid> ... </instance> ...
     </instances>
     <lastExt> _ => N </lastExt>

rule @extract(N:InstanceName, F:FieldName : CW:ConstValue ( _:FieldMods ) ; Rest:FieldDecs ) =>
        @extractField(N,F,CW) ~> @extract(N,Rest)
rule <k> @extract(N:InstanceName, F:FieldName : * (_:FieldMods); Rest:FieldDecs) =>
    @setVarWidth(@evalLengthExp(LE,N) * @val(8,0,false) - @val(FW,0,false)) ~> @extractField(N,F,@getVarWidth) ~> @extract(N,Rest) ... </k>
    <instances>
        <instance> <name> N </name> <typeName> H:HeaderTypeName </typeName> ... </instance> ...
    </instances>
    <headers>
        <header> <name> H </name> <opts> ("length" |-> LE:LengthExp) ("$fixed_width" |-> FW:Int) _:Map </opts>  ... </header> ...
    </headers>
//TODO: exception if more than max_length

syntax KItem ::= "@setVarWidth" "(" K /* Val */ ")" [strict]
rule <k> @setVarWidth(V:Val) => . ... </k>
     <parser> <varWidth> .K => V </varWidth> ... </parser>

syntax KItem ::= "@getVarWidth"
rule <k> @getVarWidth => V ... </k>
     <parser> <varWidth> V:Val </varWidth> ... </parser>

syntax LengthExp ::= Val
syntax LengthExp ::= "@evalLengthExp" "(" LengthExp ","  InstanceName ")"
rule @evalLengthExp(CV:ConstValue, _:InstanceName) => CV
rule <k> @evalLengthExp(F:FieldName, N:InstanceName) => V ... </k>
    <instances>
        <instance> <name> N </name> <fieldVals> F |-> V:Val _:Map </fieldVals>  ... </instance> ...
    </instances>
rule @evalLengthExp(LE1:LengthExp * LE2:LengthExp, N:InstanceName) => @evalLengthExp(LE1, N) * @evalLengthExp(LE2, N)
rule @evalLengthExp(LE1:LengthExp + LE2:LengthExp, N:InstanceName) => @evalLengthExp(LE1, N) + @evalLengthExp(LE2, N)
rule @evalLengthExp(LE1:LengthExp - LE2:LengthExp, N:InstanceName) => @evalLengthExp(LE1, N) - @evalLengthExp(LE2, N)
rule @evalLengthExp(LE1:LengthExp << LE2:LengthExp, N:InstanceName) => @evalLengthExp(LE1, N) << @evalLengthExp(LE2, N)
rule @evalLengthExp(LE1:LengthExp >> LE2:LengthExp, N:InstanceName) => @evalLengthExp(LE1, N) >> @evalLengthExp(LE2, N)

syntax KItem ::= "@extractField" "(" InstanceName "," FieldName "," K /* Val */ ")" [strict(3)]

//TODO: array
rule <k> @extractField(N:InstanceName, F:FieldName , W:Val ) => @initField(N,F,@extractFieldValFromPacket(@packetAt(Packet, I) , @getAttr(F,Fs))) ... </k>
     <instances>
        <instance> <name> N </name>  <typeName> H:HeaderTypeName </typeName>  ... </instance>
        ...
     </instances>
     <headers>
              <header> <name> H </name> <fields> Fs:FieldDecs </fields> ... </header>
              ...
     </headers>
     <packet> Packet:List </packet>
     <index> I:Int => I +Int 1 </index>

syntax Val ::= "@packetAt" "(" List ","  Int ")" [function]
rule @packetAt(ListItem(X) _:List, 0) => X
rule @packetAt(ListItem(_) Rest:List, I:Int) => @packetAt(Rest, I -Int 1) when I >Int 0


syntax KItem ::=   "@writeFieldAdjusted" "(" InstanceName "," FieldName "," K /* Val */ ")" [strict(3)]
                 | "@writeFieldAdjusted" "(" FieldRef "," K /* Val */ ")" [strict(2)]
rule @writeFieldAdjusted( I:InstanceName . F:FieldName, V:Val) => @writeFieldAdjusted(I,F,V) //todo array acceess
rule <k> @writeFieldAdjusted(N,F,V:Val) => @writeField(N,F,@adjustVal(@getAttr(F,Fs),V)) ...</k>
          <instances>
             <instance> <name> N </name>  <typeName> H:HeaderTypeName </typeName>  ... </instance>
             ...
          </instances>
          <headers>
            <header> <name> H </name> <fields> Fs:FieldDecs </fields> ... </header>
            ...
          </headers>

syntax KItem ::= "@writeField" "(" InstanceName "," FieldName "," K /* Val */ ")" [strict(3)]
rule <k> @writeField(N,F,V:Val) => . ...</k>
        <instances>
            <instance> <name> N </name> <valid> true </valid>  <fieldVals> FV:Map => FV [ F <- V ] </fieldVals>  ... </instance>
            ...
        </instances>

rule <k> @writeField(N,F,V:Val) => . ...</k>
        <instances>
            <instance> <name> N </name> <valid> false </valid>  ... </instance>
            ...
        </instances>
//no change if the field is not valid

//TODO: change FieldDec to FieldAttr which should be custom format for field attributes
syntax FieldDec ::= "@getAttr" "(" FieldName "," FieldDecs ")" [function]
rule @getAttr (F:FieldName, F : W:BitWidth ( M:FieldMods ); _:FieldDecs) => F : W (M);
rule @getAttr (F1:FieldName, F2:FieldName : _:BitWidth ( _:FieldMods ); Rest:FieldDecs) =>
        @getAttr(F1,Rest) when  F1 =/=K F2

syntax KItem /* Val */ ::= "@adjustVal" "(" FieldDec "," K /* Val */ ")" [strict(2)]
rule @adjustVal( _:FieldName : Wd:UnsignedValue ( FM:FieldMods ) ;, V:Val )  //TODO (minor) : Wd should be ConstValue
    => @adjustVal(USgnVal2Int(Wd),@isSigned(FM),@isSaturating(FM), V)
rule <k> @adjustVal (_:FieldName : * ( FM:FieldMods ) ;, V:Val) => @adjustVal(W,@isSigned(FM),@isSaturating(FM), V) ...</k>
     <varWidth> @val(W:Int,_,_) </varWidth>

syntax KItem /* Val */ ::= "@adjustVal" "(" Map "," K /* Val */ ")" [strict(2)]
rule @adjustVal("$width" |-> W:Int "$signed" |-> Sg:Bool "$saturating" |-> St:Bool _:Map , V:Val) => @adjustVal(W,Sg,St,V)

syntax KItem /* Val */ ::= "@adjustVal" "(" Int "," Bool "," Bool "," K /* Val */ ")" [strict(4)]
rule @adjustVal(W2:Int,Sg2:Bool,St:Bool,@val(V,W1,Sg1)) =>
       @val(V,W2,Sg2)
//TODO: (VERY IMPORTANT ***): fix and complete this ***************************************

syntax Bool ::= "@isSigned" "(" FieldMods ")" [function]
rule @isSigned(.FieldMods) => false
rule @isSigned(signed , Rest:FieldMods) => true
rule @isSigned(saturating , Rest:FieldMods) => @isSigned(Rest:FieldMods)


syntax Bool ::= "@isSaturating" "(" FieldMods ")" [function]
rule @isSaturating(.FieldMods) => false
rule @isSaturating(saturating , Rest:FieldMods) => true
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

//----------------verify/update calc fields------------------
//verify
syntax KItem ::=   "@verifyCalcFields"
                 | "@verifyCalcFields" "(" K ")"

rule <k> @verifyCalcFields => @verifyCalcFields(S) ... </k>
     <calcFieldSet> S:Set </calcFieldSet>

rule @verifyCalcFields(.Set) => .
rule @verifyCalcFields(SetItem(F:FieldRef) Rest:Set) => @verifyCalcField(F) ~> @verifyCalcFields(Rest)


syntax KItem ::=   "@verifyCalcField" "(" FieldRef ")"
                 | "@verifyCalcField" "(" FieldRef "," List ")"



//TODO: array (?)
rule <k> @verifyCalcField(H:InstanceName . F:FieldName) => .  ... </k>
     <instances> <instance> <name> H </name> <valid> false </valid> ... </instance> ... </instances>
rule <k> @verifyCalcField(H:InstanceName . F:FieldName) => @verifyCalcField(H.F, V)  ... </k>
         <instances> <instance> <name> H </name> <valid> true </valid> ... </instance> ... </instances>
         <calcFields> <calcField> <fieldRef> H.F </fieldRef> <verifies> V:List </verifies> ... </calcField> </calcFields>

rule @verifyCalcField(_:FieldRef, .List) => .
rule @verifyCalcField(F:FieldRef, ListItem(verify FLC:FieldListCalculationName if (C:CalcBoolCond);) Rest:List) =>
        @if (C) @then
            (@if (F %== @calculateFLC(FLC)) @then //probably should check width
                .K
             @else
                //$pause right now the checksum is a dummy number
                .K //TODO: parser exception
            )
        @else
            @verifyCalcField(F, Rest)


rule CalcBCEq(F:FieldRef, V:FieldValue) => V %== F

syntax KItem ::= "@calculateFLC" "(" FieldListCalculationName ")"
rule <k> @calculateFLC(N:FieldListCalculationName) => @calculateChecksum(@concat(@readFieldList(E)), A, W) ... </k>
     <fieldListCalcs> <fieldListCalc> <name> N </name> <fLists> L:List </fLists> <algorithm> A:StreamFunctionAlgorithmName </algorithm> <outWidth> W:Int </outWidth> <fListIndex> I:Int </fListIndex> ... </fieldListCalc> ... </fieldListCalcs>
     <fieldLists> <fieldList> <name> FN:FieldListName </name> <fields> E:FieldListEntryItems </fields> ... </fieldList> ... </fieldLists>
     when L[I] ==K ListItem(FN)


syntax KItem ::=   "@readFieldList" "(" FieldListEntryItems ")"

rule @readFieldList(.FieldListEntryItems) => @nil
rule @readFieldList(F:FieldRef ; Rest:FieldListEntryItems) => @if @isValid(F) @then @makeCons(@readField(F), @readFieldList(Rest)) @else @readFieldList(Rest)
rule @readFieldList(V:FieldValue ; Rest:FieldListEntryItems) => @makeCons(V, @readFieldList(Rest))
rule <k> @readFieldList(N:FieldListName ; Rest:FieldListEntryItems) => @makeConcat(@readFieldList(E),@readFieldList(Rest)) ... </k>
     <fieldLists> <fieldList> <name> N </name> <fields> E:FieldListEntryItems </fields> ... </fieldList> ... </fieldLists>
rule <k> @readFieldList(N:InstanceName ; Rest:FieldListEntryItems) => @readFieldList(@getFieldsAsFLI(N,F,Rest)) ... </k> //todo: array
     <instances> <instance> <name> N </name> <typeName> H:HeaderTypeName </typeName> ...   </instance> ... </instances>
     <headers> <header> <name> H </name> <fields> F:FieldDecs </fields> ... </header> ... </headers>
//TODO rule @readFieldList(payload ; Rest:FieldListEntryItems) => @makeCons(V, @readFieldList(Rest))


syntax FieldListEntryItems ::= "@getFieldsAsFLI" "(" HeaderRef "," FieldDecs ","  FieldListEntryItems ")" [function]
rule @getFieldsAsFLI(H:HeaderRef , F:FieldName : _:BitWidth  ( _:FieldMods ); Rest:FieldDecs, FLI:FieldListEntryItems) => @getFieldsAsFLI(H,Rest, H.F ; FLI)
rule @getFieldsAsFLI(_:HeaderRef , .FieldDecs , FLI:FieldListEntryItems) => FLI

syntax KItem ::= "@calculateChecksum" "(" K /* Val */ "," StreamFunctionAlgorithmName "," Int ")" [strict(1)]
//TODO: fix this, need to create a hook in k
rule @calculateChecksum (_:Val,_:StreamFunctionAlgorithmName,W:Int) => @val(0,W,false)


//update

syntax KItem ::=   "@updateCalcField" "(" FieldRef "," List "," Val ")"

rule @updateCalcField(_:FieldRef, .List, V:Val) => V
rule @updateCalcField(F:FieldRef, ListItem(update FLC:FieldListCalculationName if (C:CalcBoolCond);) Rest:List, V:Val) =>
        @if (C) @then
            @calculateFLC(FLC)
        @else
            @updateCalcField(F, Rest, V)

//----------------control flow-------------------------
rule .ControlStatements => .                                [structural] //TODO: maybe add a default action
rule S:ControlStatement Rest:ControlStatements => S ~> Rest [structural]
rule { B:ControlStatements } => B                            [structural]

//apply
rule apply (T:TableName) ; => apply (T) { .HitMissCases }   [macro]


//TODO: for now assuming that a screenshot of current rules are taken before matching
rule <k> apply (T:TableName) { C:CaseList } => @setCrntTable(T) ~> @checkNextRule(FM,R) ~> @setCrntTable(.K) ~> C ... </k>
     <tables>
        <table> <name> T </name> <reads> FM:FieldMatchs </reads> <rules> R:List </rules> ... </table>
     ...
     </tables>

//select
rule A:ActionName ~>  @setCrntTable(.K) ~> C:CaseList  => @setCrntTable(.K) ~> @checkNextAppSelCase (A,C)

syntax KItem ::= "@checkNextAppSelCase" "(" ActionName "," CaseList ")"
rule @checkNextAppSelCase(_,.ActionCases) => .
rule @checkNextAppSelCase(_,.HitMissCases) => .
rule @checkNextAppSelCase(A:ActionName, HM:HitOrMiss B:ControlBlock Rest:HitMissCases) =>
    #if ((HM ==K miss andBool A ==K @miss ) orBool (HM ==K hit andBool A =/=K @miss)) #then
        B
    #else
        @checkNextAppSelCase(A,Rest)
    #fi

rule @checkNextAppSelCase(A:ActionName, AD:ActionOrDefault B:ControlBlock Rest:ActionCases) =>
   #if (@isDefault(AD) orBool A ==K AD) #then
       B
   #else
       @checkNextAppSelCase(A,Rest)
   #fi

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
        @if B @then T @else F


//call
rule <k> F:ControlFunctionName () ; => Body  ... </k>
     <controlFlows>
        <control> <name> F </name> <body> Body </body> ... </control>
        ...
     </controlFlows>
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
rule @val(V1,_,_) ^ @val(V2,_,_) => @val(V1 ^Int V2,0,true)
rule NotExp(@val(V2,_,_)) => @val(~Int V2,0,true)
// TODO ISSUE: the semantics of none of these operators is exactly
// defined specially when it comes to width, so leaving it like this
// for now.

//rule MinusExp(@val(V:Int,0,_)) =>  @val(0 -Int V,0,true)
//rule MinusExp(@val(V:Int,W,_)) =>  @val(0 -Int V,W +Int 1,true) when W >Int 0
//TODO: unify it with @negative

rule BExpValid( H:InstanceName )   => @isValid(H)

rule B1:Bool or B2:Bool => B1 orBool B2
rule B1:Bool and B2:Bool => B1 andBool B2
//TODO ISSUE: short circuit ?

//---------------table match-----------------------------
syntax KItem ::= "@checkNextRule" "(" FieldMatchs "," List /*rules*/ ")"

//TODO: check defualt action
//TODO: what else todo
//TODO: assumming rules are checked for consistency at the time of insertion and are  are sorted by their priority


syntax ActionName ::= "@miss" [token]
rule @checkNextRule(_:FieldMatchs,.List  ) => @miss
rule @checkNextRule(FM:FieldMatchs, ListItem($rule(Id:Int, $ctr(R:List),CD:ActionCallOrActionProfileRef )) Rest:List)
    => @if @matchAll(FM,R) @then @setCrntRule(Id) ~> @updateDirectStatefuls ~> @callOrDeref(CD) ~> @setCrntRule(.K)  @else @checkNextRule(FM,Rest)

rule A:ActionName ~> @setCrntRule(.K) => @setCrntRule(A) ~> A

syntax KItem /* Bool */ ::= "@matchAll" "(" FieldMatchs "," List /*criteria*/  ")"
rule @matchAll(.FieldMatchs,.List) => true
rule @matchAll(FMR:FieldOrMaskedRef : MT:FieldMatchType ; R1:FieldMatchs, ListItem(V:K) R2:List)
    => @match(@readFMRef(FMR,MT),V,MT) %&& @matchAll(R1,R2)

syntax KItem /* Bool */ ::= "@match" "(" K /* KResult */ "," K /* KResult */ "," FieldMatchType  ")" [strict(1,2)]
rule @match(V1:Val,V2:Val,exact) => V1 == V2    //TODO ISSUE: is this it?
rule @match(V1:Val,$pair(V2:Val,M:Val),ternary) => (V1 & M) == (V2 & M)
rule @match(V1:Val,$pair(V2:Val,M:Val),lpm) => (V1 & M) == (V2 & M)
rule @match(V1:Val,$pair(L:Val,H:Val),range) => (V1 >= L) and (V1 <= H)
rule @match(B1:Bool,B2:Bool,valid) => B1 ==Bool B2

syntax KItem /* KResult */ ::= "@readFMRef" "(" FieldOrMaskedRef "," FieldMatchType  ")"


rule @readFMRef(F:FieldRef,FM:FieldMatchType) => #if FM =/=K valid #then @readField(F) #else @isValid(F) #fi
rule @readFMRef(F:FieldRef mask M:ConstValue,_)  => @applyMask(@readField(F),M)
// "Header references for matching may only be used with the valid match type."
rule @readFMRef(H:HeaderRef,valid) => @isValid(H)


syntax KItem ::= "@setCrntRule" "(" K ")"
rule <k> @setCrntRule(V:K) => . ... </k>
     <crntRule> _ => V </crntRule>

syntax KItem ::= "@setCrntTable" "(" K ")"
rule <k> @setCrntTable(V:K) => . ... </k>
     <crntTable> _ => V </crntTable>

//--------------statefuls--------------------------------

syntax KItem ::=  "@updateDirectStatefuls"
                | "@updateDirectStatefuls" "(" K /* ::Set */ ")"
rule <k> @updateDirectStatefuls => @updateDirectStatefuls(S) ... </k>
     <tableDirects> T |-> S:Set _:Map </tableDirects>
     <crntTable> T:TableName </crntTable>
rule <k> @updateDirectStatefuls => . ... </k>
     <tableDirects> M:Map </tableDirects>
     <crntTable> T:TableName </crntTable>
     when notBool #in_keys(T,M)
rule <k> @updateDirectStatefuls(SetItem(N:Id) Rest:Set) => #if (T ==K $counter) #then @updateCounter(N, CR) #else @updateMeter(N, CR, #castToFieldRef(M["$result"])) #fi ~> @updateDirectStatefuls(Rest) ... </k>
      <statefuls> <stateful> <name> N </name> <stype> T:StatefulType </stype> <opts> M:Map </opts> ... </stateful> ... </statefuls>
      <crntRule> CR:Int </crntRule>
      when (T ==K $meter) impliesBool #in_keys("$result", M) //the result attribute is required if a meter is declared with the direct attribute
rule @updateDirectStatefuls(.Set) => .

syntax KItem ::= "@updateCounter" "(" Id "," Int ")"
rule <k> @updateCounter (C:Id , I:Int) => @writeStatefulAdjusted(C, I, @readStateful(C, I) %+ #if (T ==K #token("packets","CounterType@STATEFUL-SYNTAX")) #then @val(1,0,false) #else S #fi) ... </k>
     <statefuls> <stateful> <name> C </name> <opts> "$counter_type" |-> T:CounterType _:Map </opts> ... </stateful> ... </statefuls>
     <packetSize> S:Val </packetSize>

syntax KItem ::=  "@updateMeter" "(" Id "," Int "," FieldRef")"
rule @updateMeter(M:Id, I:Int , F:FieldRef) => @writeStatefulAdjusted(M, I, @doUpdateMeter(M, I)) ~> @if @isValid(F) @then @writeFieldAdjusted(F, @readStateful(M,I)) @else .K


syntax KItem ::= "@doUpdateMeter" "(" Id "," Int ")"
rule @doUpdateMeter(_,_) => @val(0,2,false)
//TODO (minor): doing nothing for the meter

syntax KItem ::= "@writeStatefulAdjusted" "(" Id "," Int "," K /*Val*/ ")" [strict(3)]
rule <k> @writeStatefulAdjusted(N:Id, I:Int, V:Val) => @writeStateful(N, I, @adjustVal(Opts["$width" <- W],V)) ... </k>
      <statefuls> <stateful> <name> N </name> <opts> Opts:Map </opts> <width> W:Int </width> ... </stateful> ... </statefuls>

syntax KItem ::= "@writeStateful" "(" Id "," Int "," K /*Val*/ ")" [strict(3)]
rule <k> @writeStateful (N:Id, I:Int, V:Val) => . ... </k>
     <statefuls> <stateful> <name> N </name> <vals> M => M [I <- V] </vals> ... </stateful> ... </statefuls>

syntax KItem /* Val */ ::= "@readStateful" "(" Id "," Int ")"
rule <k> @readStateful (N:Id, I:Int) =>  V  ... </k>
     <statefuls> <stateful> <name> N </name> <vals> (I |-> V:Val) _:Map </vals> ... </stateful> ... </statefuls>
rule <k> @readStateful (N:Id, I:Int) => @writeStatefulAdjusted(N, I, @val(0,0,false)) ~> @readStateful(N, I) ... </k>          //TODO ISSUE: what should be inital value of meters and registers? for now, assuming 0
     <statefuls> <stateful> <name> N </name> <vals> M:Map </vals> <width> W:Int </width> <opts> Opts:Map </opts> ... </stateful>  ... </statefuls>
     when notBool #in_keys(I,M)



//K's in_keys is not implemented
syntax Bool ::= "#in_keys" "(" K "," Map ")" [function]
rule #in_keys(_:K, .Map) => false
rule #in_keys(K1:K, (K1 |-> V:K) _:Map) => true
rule #in_keys(K1:K, (K2:K |-> V:K) Rest:Map) => #in_keys(K1,Rest) when K1 =/=K K2

//---------------actions----------------------------------
syntax Arg ::= Val
syntax KItem ::= "@resolveArgs" "(" Args "," ResolvedArgs ")"
rule @resolveArgs(.Args,R:ResolvedArgs) => R
rule @resolveArgs((FR:FieldRef , Rest:Args) => Rest,$resolved(_:List (.List => ListItem(FR))))  //we do not evaluate fieldref
rule @resolveArgs(F:FieldValue , Rest:Args,R:ResolvedArgs) => F ~> @resolveArgs(Rest,R)  //a workaround 
rule (V:Val => .) ~> @resolveArgs(Rest:Args,$resolved(_:List (.List => ListItem(V))))

rule <k> @resolveArgs((X:Id , Rest:Args) => Rest,$resolved(_:List (.List => ListItem(V)))) ... </k>
     <frameStack> ListItem((X |-> V:Arg) _:Map) _:List </frameStack>
rule <k> @resolveArgs((X:Id , Rest:Args) => Rest,$resolved(_:List (.List => ListItem(X)))) ... </k>
     <instances> <instance> <name> X </name> ... </instance> ... </instances>
     <frameStack> ListItem(M:Map) _:List </frameStack> when notBool (X in keys(M))
rule <k> @resolveArgs((X:Id , Rest:Args) => Rest, $resolved(_:List (.List => ListItem(X)))) ... </k>
     <statefuls> <stateful> <name> X </name> ... </stateful> ... </statefuls>





//compound actions
rule <k> @call( A:ActionName , $resolved(Ag) ) => @pushstack ~> @bindParams(P,Ag) ~> B ~> @popstack ... </k>
     <actions>
        <action> <name> A </name> <params> P:ParamList </params> <body> B:ActionStatements </body> ... </action>
        ...
     </actions>


syntax KItem ::= "@bindParams" "(" ParamList "," List ")"
rule @bindParams(.ParamList, .List) => .
rule <k> @bindParams((P:ParamName , PR:ParamList), ListItem(A:Arg) AR:List) => @bindParams(PR,AR) ... </k>
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

//replace multiple rules with check for KLabel (i.e K REFLECTION)
syntax Id ::= "modify_field" [token]
rule @call (modify_field , $resolved(ListItem(D:FieldRef) ListItem(S:FieldRef) Rest:List)) =>
            //@if @isValid(S) @then
                @readField(S) ~> @call(modify_field,$resolved(ListItem(D) ListItem(S) Rest))
            //@else
            //  .

rule (V:Val => .) ~> @call(modify_field , $resolved(ListItem(_) ListItem(_ => V) _:List))
rule @call (modify_field , $resolved(ListItem(I:InstanceName.F:FieldName) ListItem(S:Val) ListItem(M:Val))) =>
           //@if @isValid(I.F) @then
                @writeFieldAdjusted(I,F, (@readField(I.F) %& (~ M)) %| (S %& M))
           //@else
           //     .

rule @call (modify_field , $resolved(ListItem(I:InstanceName.F:FieldName) ListItem(S:Val))) =>
           //@if @isValid(I.F) @then
                @writeFieldAdjusted(I,F, S)
           //@else
           //    .


syntax Id ::= "subtract_from_field" | "add_to_field" [token]
rule @call (subtract_from_field, $resolved(ListItem(D:FieldRef) ListItem(V:K))) =>
          @call (subtract, $resolved(ListItem(D) ListItem(D) ListItem(V)))

rule @call (add_to_field, $resolved(ListItem(D:FieldRef) ListItem(V:K))) =>
          @call (add, $resolved(ListItem(D) ListItem(D) ListItem(V)))


syntax Id ::= "subtract" | "add" [token]
rule @call (F:Id, $resolved(ListItem(D:FieldRef) ListItem(V1:FieldRef) ListItem(V2))) =>
        //@if @isValid(V1) @then
		    @readField(V1) ~> @call(F,$resolved(ListItem(D) ListItem(V1) ListItem(V2)))
	    //@else
		//    .
		when (F ==K subtract) orBool (F ==K add)

rule (V:Val => .) ~> @call(F:Id , $resolved(ListItem(_) ListItem(_ => V) _:List)) when (F ==K subtract) orBool (F ==K add)
rule @call (F:Id, $resolved(ListItem(D:FieldRef) ListItem(V1:Val) ListItem(V2:FieldRef))) =>
         //@if @isValid(V2) @then
                @readField(V2) ~> @call(subtract,$resolved(ListItem(D) ListItem(V1) ListItem(V2)))
         //@else
         //      .
        when (F ==K subtract) orBool (F ==K add)

rule (V:Val => .) ~> @call(F:Id , $resolved(ListItem(_) ListItem(_:Val) ListItem(_ => V))) when (F ==K subtract) orBool (F ==K add)
rule @call (F:Id, $resolved(ListItem(D:FieldRef) ListItem(V1:Val) ListItem(V2:Val)))
	=> #if (F ==K add) #then V1 + V2 #else V1 - V2 #fi ~> @call (modify_field, $resolved(ListItem(D:FieldRef) ListItem(.K)))
	when (F ==K subtract) orBool (F ==K add)
//TODO: implement the rest of the primitive functions



syntax Id ::= "count" [token]
rule <k> @call (count , $resolved(ListItem(C:Id) ListItem(@val(I:Int,_,_)))) => @getStatefulIndexInActionCall(C, I) ~> @updateCounter(C, 0) ... </k>
     <statefuls> <stateful> <name> C </name> <stype> $counter </stype>  ... </stateful> ... </statefuls>
rule I:Int ~> @updateCounter(C:Id, 0) => @updateCounter(C, I)

syntax Id ::= "execute_meter" [token]
rule <k> @call (execute_meter , $resolved(ListItem(C:Id) ListItem(@val(I:Int,_,_)) ListItem(F:FieldRef))) => @getStatefulIndexInActionCall(C, I) ~> @updateMeter(C, 0, F) ... </k>
     <statefuls> <stateful> <name> C </name> <stype> $meter </stype>  ... </stateful> ... </statefuls>
rule I:Int ~> @updateMeter(C:Id, 0, F:FieldRef) => @updateMeter(C, I, F)

syntax Id ::= "register_read" [token]
rule <k> @call (register_read , $resolved(ListItem(F:FieldRef) ListItem(C:Id) ListItem(@val(I:Int,_,_)))) => @getStatefulIndexInActionCall(C, I) ~> @writeFieldAdjusted(F, @readStateful(C, 0)) ... </k>
     <statefuls> <stateful> <name> C </name> <stype> $register </stype>  ... </stateful> ... </statefuls>
rule I:Int ~> @writeFieldAdjusted(F, @readStateful(C, 0)) => @writeFieldAdjusted(F, @readStateful(C, I))

syntax Id ::= "register_write" [token]
rule @call (register_write , $resolved(ListItem(C:Id) ListItem(I:Val) ListItem(F:FieldRef) )) => @readField(F) ~> @call (register_write , $resolved(ListItem(C) ListItem(I) ListItem(F) ))
rule V:Val ~> @call (register_write , $resolved(ListItem(C) ListItem(I) ListItem(F) )) => @call (register_write , $resolved(ListItem(C) ListItem(I) ListItem(V) ))
rule <k> @call (register_write , $resolved(ListItem(C:Id) ListItem(@val(I:Int,_,_)) ListItem(V:Val) )) => @getStatefulIndexInActionCall(C, I) ~> @writeStatefulAdjusted(C, 0, V) ... </k>
     <statefuls> <stateful> <name> C </name> <stype> $register </stype>  ... </stateful> ... </statefuls>
rule I:Int ~> @writeStatefulAdjusted(C, 0, V) => @writeStatefulAdjusted(C, I, V)

syntax KItem ::= "@getStatefulIndexInActionCall" "(" Id "," Int ")"
rule <k> @getStatefulIndexInActionCall(C:Id, I:Int) => #if (B ==K $direct) #then CR #else I #fi   ... </k>
     <statefuls> <stateful> <name> C </name> <stype> T:StatefulType </stype> <opts> "$binding" |-> B:BindingType M:Map </opts> ... </stateful> ... </statefuls>
     <crntTable> CT:TableName </crntTable>
     <crntRule> CR:Int </crntRule>
     when
        ((B ==K $direct) impliesBool (T =/=K $counter)) andBool
        ((B =/=K $static_global) impliesBool (#in_keys("$table", M) andBool (M["$table"] ==K CT))) andBool
        ((B =/=K $direct) impliesBool (#in_keys("$instant_count", M) andBool (I <Int #get_instant_count(M))))

syntax Int ::= "#get_instant_count" "(" Map ")" [function]
rule #get_instant_count ("$instant_count" |-> I:Int _:Map) => I

//-------------------action profile-------------------------
syntax KItem ::= "@callOrDeref" "(" ActionCallOrActionProfileRef ")"
rule @callOrDeref(@call(A:ActionName, X)) => @call(A,X) ~> A
rule <k> @callOrDeref(@apref(Id:Int)) => @deref(P, Id) ... </k>
     <tables> <table> <name> T </name> <acts> action_profile: P:ActionProfileName  ;</acts> ... </table> ... </tables>
     <crntTable> T:TableName </crntTable>

syntax KItem ::= "@deref" "(" ActionProfileName "," Int ")"
rule <k> @deref(P:ActionProfileName , Id:Int) => @callOrDeref(C) ... </k>
     <actionProfiles> <actionProfile> <name> P </name> <entries> Id |-> C:ActionCall _:Map </entries> ... </actionProfile> ... </actionProfiles>
rule <k> @deref(P:ActionProfileName , Id:Int) => @calculateFLC(FLC) ~> @deref(P,Id) ... </k>
     <actionProfiles> <actionProfile> <name> P </name> <entries> Id |-> G:List _:Map </entries> <opts> "$selector" |-> S:SelectorName _:Map </opts> ... </actionProfile> ... </actionProfiles>
     <actionSelectors> <actionSelector> <name> S </name> <key> FLC:FieldListCalculationName </key> ... </actionSelector> ... </actionSelectors>
rule <k> @val(I:Int,_,false) ~> @deref(P:ActionProfileName , Id:Int) => @callOrDeref(#castToActionCall(G[I modInt size(G)])) ... </k>
     <actionProfiles> <actionProfile> <name> P </name> <entries> (Id |-> G:List) _:Map </entries> <opts> "$selector" |-> S:SelectorName _:Map </opts> ... </actionProfile> ... </actionProfiles>
     <actionSelectors> <actionSelector> <name> S </name> <key> FLC:FieldListCalculationName </key> ... </actionSelector> ... </actionSelectors>

syntax ActionCall ::= "#castToActionCall" "(" K ")" [function]
//rule #castToActionCall(X:ActionCall) => X
rule #castToActionCall(ListItem(X:ActionCall)) => X //workaround for K issue #2343


//-------------------deparsing------------------------------
syntax Id ::= "egress" [token]
rule <k> @egress => (#if @egressDefined(/*<controlFlows>*/ S /*</controlFlows>*/) #then egress (); #else . #fi) ~> @deparseNext(L) ... </k>
     <dporder> L:List </dporder>
//     <controlFlows> S </controlFlows>
     <cfset> S </cfset> //TODO: temporary fix for K issue #2279

syntax Bool ::= "@egressDefined" "(" Set ")" [function]
rule @egressDefined(S) => notBool notBool (egress in S) //workaround to get rid of ambiguities

//syntax Bool ::= "@egressDefined" "(" K ")" [function]
//rule @egressDefined(<controlFlows> <control> <name> F:ControlFunctionName </name> ... </control> Rest </controlFlows>) =>
//	#if F ==K egress #then true #else @egressDefined(<controlFlows> Rest </controlFlows> #fi
//rule @egressDefined(<controlFlows> .Bag </controlFlows>) => false

syntax KItem ::= "@deparseNext" "(" List ")"
rule @deparseNext(ListItem(H:HeaderExtractRef) Rest:List) => @deparseHeader(H) ~> @deparseNext(Rest) [structural]
rule @deparseNext(.List) => .                                                             [structural]

syntax KItem ::= "@deparseHeader" "(" HeaderExtractRef ")"
rule <k> @deparseHeader(I:InstanceName) => #if M ==Bool false #then .K #else @deparseFields(I,F) #fi ...</k>
        <instances>
            <instance> <name> I </name> <typeName> H:HeaderTypeName </typeName> <valid> M:Bool </valid>  ... </instance>
            ...
        </instances>
        <headers>
            <header> <name> H </name> <fields> F:FieldDecs </fields>  ... </header>
            ...
        </headers>
//TODO:array

syntax KItem ::= "@deparseFields" "(" InstanceName "," FieldDecs ")"
rule @deparseFields(I:InstanceName,F:FieldName : _:ConstValue ( _:FieldMods ) ; Rest:FieldDecs) =>
        @deparseField(I,F) ~> @deparseFields(I,Rest)        [structural]
rule @deparseFields(I:InstanceName,F:FieldName : * ( _:FieldMods ) ; Rest:FieldDecs) =>
        @deparseField(I,F) ~> @deparseFields(I,Rest)        [structural]
rule @deparseFields(_:InstanceName,.FieldDecs) => .        [structural]


syntax KItem ::= "@deparseField" "(" InstanceName "," FieldName ")"
rule <k> @deparseField(I:InstanceName,F:FieldName) => @packetOut(V /*@FieldVal2String(V,@getAttr(F,Fs))*/) ...</k>
         <instances>
             <instance> <name> I </name> <typeName> H:HeaderTypeName </typeName> <fieldVals> F |-> V:Val ...</fieldVals> ... </instance>
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
          <instance> <name> I </name> <typeName> H:HeaderTypeName </typeName> <fieldVals> F |-> V:Val ...</fieldVals> ... </instance>
          ...
      </instances>
      <headers>
          <header> <name> H </name> <fields> Fs:FieldDecs </fields> ... </header>
         ...
      </headers>
      <calcFields> <calcField> <fieldRef> I . F </fieldRef> <updates> U:List </updates> ... </calcField> ... </calcFields>

//syntax KResult ::= String
//syntax KItem ::= "@packetOut" "(" K /* String */ ")" [strict]
//rule <k> @packetOut(S:String) => . ... </k>
//     <packetout> P:String => P +String S </packetout>
syntax KItem ::= "@packetOut" "(" K /* Val */ ")" [strict]
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




//------------------utils-------------------------------
syntax Int ::= "Val2Int" "(" Val ")" [function]
rule Val2Int ( @val(I:Int,_,_) ) => I


syntax Id ::= BinaryValueToken | DecimalValueToken | HexadecimalValueToken
syntax Int ::= "USgnVal2Int" "(" ConstValue ")" [function]
//TODO: change all letters to lower case
rule USgnVal2Int( UV:BinaryValueToken ) => String2Base(replaceFirst(replaceAll(Id2String(UV),"_",""),"0b",""),2)
rule USgnVal2Int( UV:DecimalValueToken ) => String2Int(replaceAll(Id2String(UV),"_",""))
rule USgnVal2Int( UV:HexadecimalValueToken ) => String2Base(replaceFirst(replaceAll(Id2String(UV),"_",""),"0x",""),16)


syntax K ::= "@if" K /* Bool */ "@then" K "@else" K [strict(1)]
syntax KResult ::= Bool
rule @if true @then T:K @else F:K => T  [transition]
rule @if false @then T:K @else F:K => F [transition]


syntax KItem /* Val */ ::= "@concat" "(" K /* Vals */ ")" [strict]

rule @concat(@cons(V:Val,@nil)) => V
rule @concat(@cons(@val(V1:Int,W1:Int,S1:Bool),@cons(@val(V2:Int,W2:Int,S2:Bool), Rest:Vals))) => @concat(@cons(@val((@intrepretUnsigned(@val(V1,W1,S1)) <<Int W2) +Int @intrepretUnsigned(@val(V2,W2,S2))   ,W1 +Int W2,false),Rest))



syntax Int ::= "@intrepretUnsigned" "(" Val ")" [function]
rule @intrepretUnsigned(@val(V:Int,_,false)) => V
//rule @intrepretUnsigned(@val(V:Int,W:Int,true)) => V //TODO

//TODO:temporary, maybe we want to resolve the referece to header first
//If not, complete it is for array
syntax KItem /* Val */ ::= "@readField" "(" K /* FieldRef */ ")"
rule <k> @readField(H:InstanceName . F:FieldName) => V ... </k>
      <instances>
         <instance> <name> H </name> <valid> true </valid> <fieldVals> (F |-> V:Val) _:Map </fieldVals> ...  </instance> ...
      </instances>

//new in version 1.0.4
rule <k> @readField(H:InstanceName . F:FieldName) => @undef ... </k>
      <instances>
         <instance> <name> H </name> <valid> false </valid>  ...  </instance> ...
      </instances>




//TODO: same as above
syntax KItem /* Bool */ ::= "@isValid" "(" K /* FieldRef or HeaderRef */ ")"
rule <k> @isValid(H:InstanceName . _:FieldName) => V ... </k>
      <instances>
         <instance> <name> H </name> <valid> V:Bool </valid>  ...  </instance> ...
      </instances>

rule <k> @isValid(H:InstanceName) => V ... </k>
      <instances>
         <instance> <name> H </name> <valid> V:Bool </valid>  ...  </instance> ...
      </instances>



syntax KItem /* Val */ ::= "@applyMask" "(" K /* Val */ "," K /* Val */ ")" [strict]
rule @applyMask(V1:Val,V2:Val) => V1 & V2
//TODO ISSUE: is this it?

syntax KItem ::=   K "%==" K [seqstrict]
                 | K "%&&" K [seqstrict]
                 | K "%&"  K [seqstrict]
                 | K "%+" K [seqstrict]
		 | K "%|"  K [seqstrict]

rule V1:Val %== V2:Val => V1 == V2
rule V1:Val %& V2:Val => V1 & V2
rule V1:Val %| V2:Val => V1 | V2
rule V1:Val %+ V2:Val => V1 + V2
rule B1:Bool %&& B2:Bool => B1 andBool B2



//------------------const value--------------------------



syntax Vals ::= "@nil" | "@cons" "(" Val "," Vals ")"
syntax KResult ::= Val | Vals

syntax KItem /* Vals */ ::= "@makeCons" "(" K /* Val */ "," K /* Vals */ ")" [seqstrict]

rule @makeCons(V:Val,Vs:Vals) => @cons (V,Vs)

syntax KItem /* Vals */ ::= "@makeConcat" "(" K /* Vals */ "," K /* Vals */ ")" [seqstrict]
rule @makeConcat(@nil, Vs:Vals) => Vs
rule @makeConcat(@cons(V:Val,Rest:Vals), Vs:Vals) => @makeCons(V,@makeConcat(Rest,Vs))


rule UV:UnsignedValue => @val(USgnVal2Int(UV),0,false)
rule + UV:UnsignedValue => UV
rule nconstv(UV:UnsignedValue) => @negative(UV)
rule (W:DecimalValueToken' UV:UnsignedValue) => @setWidth(USgnVal2Int(W),UV)
rule (+ W:WidthSpec UV:UnsignedValue) => W UV
rule nwconstv(W:WidthSpec,UV:UnsignedValue) => @negative(W UV)

syntax KItem ::= "@negative" "(" K ")" [strict]
rule @negative(@val(I:Int,W:Int,S:Bool)) => #if (notBool S) andBool (W ==Int 0) #then @val(0 -Int I,0,true) #else @val(0 -Int I,W +Int 1,true) #fi

syntax KItem ::= "@setWidth" "(" K "," K ")" [seqstrict]
rule @setWidth(@val(W:Int,0,false),@val(I:Int,0,false)) => @val(I,W,false) when I <Int (2 ^Int W)
//TODO ISSUE: what happens if the unsigned value constant does not fit into the width specified


//----------------------------casts-------------------------------------------
syntax FieldRef ::= "#castToFieldRef" "(" K ")" [function]
rule #castToFieldRef(X:FieldRef) => X


//----------------------------temporary utils----------------------------------




syntax KItem ::= "$pause"


endmodule
