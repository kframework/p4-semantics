require "network-configuration.k"



module P4-SEMANTICS
imports P4-NETWORK-COMMON
imports CONFIGURATION


//macros




//---------------- putting decralarions into configuration cells--------------------------------

syntax KItem ::=
          "@processDec" "(" K ")"

rule <k> (Dec:P4Declaration Rest:P4Declarations) => @processDec(Dec) ~> Rest ... </k>

rule <k> (.P4Declarations => .) ... </k>

// @processDec


// header dec
rule <k> @processDec(header_type Name:HeaderTypeName { fields { Fields:FieldDecs } Opt:HeaderOptionals }) => . ... </k>
    <headers>  (.Bag =>
        <header>  <name> Name </name> <opts> Opt </opts> <fields> Fields </fields>   </header>)
    ... </headers>


rule N:FieldName : W:BitWidth ; => N : W ( .FieldMods ) ; [macro]


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
        @writeField(I,F,@val(0,0,false)) ~> @initFields(I, .FieldValueAssignments, Rest)
rule @initFields(I, F:FieldName : V:FieldValue ; ARest:FieldValueAssignments, SetItem(F:FieldName) FRest:Set) =>
        @writeField(I,F,V) ~> @initFields(I, ARest, FRest)

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

rule <k> @processDec(table Name:TableName { reads { FM:FieldMatchs }  Act:TableActions Opt:TableOptionals } ) => . ... </k>
         <tables>... (.Bag =>
               <table>
                 <name> Name </name> <reads> FM </reads> <acts> Act </acts> <opts> Opt </opts> <rules> .List </rules>
               </table>
         ) ... </tables>


// control

rule <k> @processDec(control Name:ControlFunctionName { Body:ControlStatements } ) => . ... </k>
         <controlFlows> (.Bag =>
               <control>
                    <name> Name </name> <body> Body </body>
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


syntax Id ::= "standard_metadata" [token]
rule <k> @nextPacket => @parse&ingress ~> @egress ~> @txenPacket ~> @nextPacket ... </k>
     <buffer> <bin> (ListItem($packet(P:List, Port:Int)) => .List) _:List </bin> ... </buffer>
     <packet> _ => P </packet>
     <instances>
        <instance>
            <name> standard_metadata </name>
            <fieldVals> _:Map => (String2Id("ingress_port") |-> @val(Port,32,false) String2Id("egress_spec") |-> @undef) </fieldVals>
            ...
        </instance>
        ...
    </instances>
//TODO: IMPORTANT: instances must be reset




syntax KItem ::= "@txenPacket"
syntax Id ::= "egress_spec" [token]
rule <k> @txenPacket => . ... </k>
     <packetout> P:List => .List </packetout>
     <buffer> <bout>   _:List (.List => ListItem($packet(P,Port))) </bout> ... </buffer>
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
rule <k> return Control:ControlFunctionName ; => Control(); ... </k>
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

syntax KItem ::= "@extractField" "(" InstanceName "," FieldName "," K /* Val */ ")" [strict(3)]

//TODO: array
rule <k> @extractField(N:InstanceName, F:FieldName , W:Val ) => @writeField(N,F,@extractFieldValFromPacket(@packetAt(Packet, I) , @getAttr(F,Fs))) ... </k>
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


syntax KItem ::= "@writeFieldAdjusted" "(" InstanceName "," FieldName "," K /* Val */ ")" [strict(3)]
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
            <instance> <name> N </name>  <fieldVals> FV:Map => FV [ F <- V ] </fieldVals>  ... </instance>
            ...
        </instances>


//TODO: change FieldDec to FieldAttr which should be custom format for field attributes
syntax FieldDec ::= "@getAttr" "(" FieldName "," FieldDecs ")" [function]
rule @getAttr (F:FieldName, F : W:BitWidth ( M:FieldMods ); _:FieldDecs) => F : W (M);
rule @getAttr (F1:FieldName, F2:FieldName : _:BitWidth ( _:FieldMods ); Rest:FieldDecs) =>
        @getAttr(F1,Rest) when  F1 =/=K F2

syntax KItem /* Val */ ::= "@adjustVal" "(" FieldDec "," Val ")"
rule @adjustVal( _:FieldName : Wd:UnsignedValue ( _:FieldMods ) ;, @val(I,Ws,Ss) )
    => @val(I,USgnVal2Int(Wd),false)
//TODO: IMPORTANT: fix and complete this (also remember to support * )


//syntax KItem /* Val */ ::= "@String2FieldVal" "(" String "," FieldDec ")"
//rule @String2FieldVal( S:String , _:FieldName : Wd:UnsignedValue ( _:FieldMods ) ;)
//    => @val(String2Base(S,2),USgnVal2Int(Wd),false)
syntax KItem /* Val */ ::= "@extractFieldValFromPacket" "(" Val "," FieldDec ")"
rule @extractFieldValFromPacket( @val(V:Int,W:Int,S:Bool) , _:FieldName : Wd:UnsignedValue ( _:FieldMods ) ;)
    => @val(V,W,S)  when W ==Int USgnVal2Int(Wd)
                                 //    => @val(String2Base(S,2),USgnVal2Int(Wd),false)
//TODO: IMPORTANT: fix and complete this (also remember to support * )

//----------------control flow-------------------------
rule .ControlStatements => .                                [structural] //TODO: maybe add a default action
rule S:ControlStatement Rest:ControlStatements => S ~> Rest [structural]
rule { B:ControlStatements } => B                            [structural]

//apply
rule apply (T:TableName) ; => apply (T) { .HitMissCases }   [macro]


//TODO: for now assuming that a screenshot of current rules are taken before matching
rule <k> apply (T:TableName) { C:CaseList } => @checkNextRule(FM,R) ~> C ... </k>
     <tables>
        <table> <name> T </name> <reads> FM:FieldMatchs </reads> <rules> R:List </rules> ... </table>
     ...
     </tables>

//select
rule A:ActionName ~> C:CaseList  => @checkNextAppSelCase (A,C)

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
rule @checkNextRule(FM:FieldMatchs, ListItem($rule($ctr(R:List),@call(A:ActionName,$resolved(Ag)) )) Rest:List)
    => @if @matchAll(FM,R) @then @call(A,$resolved(Ag)) ~> A  @else @checkNextRule(FM,Rest)

syntax KItem /* Bool */ ::= "@matchAll" "(" FieldMatchs "," List /*criteria*/  ")"
rule @matchAll(.FieldMatchs,.List) => true
rule @matchAll(FMR:FieldOrMaskedRef : MT:FieldMatchType ; R1:FieldMatchs, ListItem(V:K) R2:List)
    => @match(@readFMRef(FMR,MT),V,MT) %&& @matchAll(R1,R2)

syntax KItem /* Bool */ ::= "@match" "(" K /* KResult */ "," K /* KResult */ "," FieldMatchType  ")" [strict(1,2)]
rule @match(V1:Val,V2:Val,exact) => V1 == V2    //TODO ISSUE: is this it?
//TODO: rule @match(V:?,M:?,ternary)
//TODO: rule @match(V:?,M:?,lmp)
//TODO: rule @match(V:?,M:?,range)
//TODO: rule @match(V:?,M:?,valid)


syntax KItem /* KResult */ ::= "@readFMRef" "(" FieldOrMaskedRef "," FieldMatchType  ")"


rule @readFMRef(F:FieldRef,FM:FieldMatchType) => #if FM =/=K valid #then @readField(F) #else @isValid(F) #fi
rule @readFMRef(F:FieldRef mask M:ConstValue,_)  => @applyMask(@readField(F),M)
// "Header references for matching may only be used with the valid match type."
rule @readFMRef(H:HeaderRef,valid) => @isValid(H)




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
     //TODO: IMPORTANT: it seems like a bug in K, X:Id matches FieldValues as well! so I used <intances> ... to make sure X in this case is a headerref





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
            @if @isValid(S) @then
                @readField(S) ~> @call(modify_field,$resolved(ListItem(D) ListItem(S) Rest))
            @else
                .
rule (V:Val => .) ~> @call(modify_field , $resolved(ListItem(_) ListItem(_ => V) _:List))
rule @call (modify_field , $resolved(ListItem(I:InstanceName.F:FieldName) ListItem(S:Val) ListItem(M:Val))) =>
           @if @isValid(I.F) @then
                @writeFieldAdjusted(I,F, (@readField(I.F) %& (~ M)) %| (S %& M))
           @else
                .
rule @call (modify_field , $resolved(ListItem(I:InstanceName.F:FieldName) ListItem(S:Val))) =>
           @if @isValid(I.F) @then
                @writeFieldAdjusted(I,F, S)
           @else
                .

syntax Id ::= "subtract_from_field" [token]
rule @call (subtract_from_field, $resolved(ListItem(D:FieldRef) ListItem(V:K))) =>
          @call (subtract, $resolved(ListItem(D) ListItem(D) ListItem(V))) 


syntax Id ::= "subtract" [token]
rule @call (subtract, $resolved(ListItem(D:FieldRef) ListItem(V1:FieldRef) ListItem(V2))) =>
         @if @isValid(V1) @then
		@readField(V1) ~> @call(subtract,$resolved(ListItem(D) ListItem(V1) ListItem(V2)))
	 @else
		.
rule (V:Val => .) ~> @call(subtract , $resolved(ListItem(_) ListItem(_ => V) _:List))
rule @call (subtract, $resolved(ListItem(D:FieldRef) ListItem(V1:Val) ListItem(V2:FieldRef))) =>
         @if @isValid(V2) @then
                @readField(V2) ~> @call(subtract,$resolved(ListItem(D) ListItem(V1) ListItem(V2)))
         @else
                .
rule (V:Val => .) ~> @call(subtract , $resolved(ListItem(_) ListItem(_:Val) ListItem(_ => V)))
rule @call (subtract, $resolved(ListItem(D:FieldRef) ListItem(V1:Val) ListItem(V2:Val)))
	=> V1 - V2 ~> @call (modify_field, $resolved(ListItem(D:FieldRef) ListItem(.K)))
//TODO: implement the rest of the primitive functions





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
rule @deparseFields(_:InstanceName,.FieldDecs) => .        [structural]


syntax KItem ::= "@deparseField" "(" InstanceName "," FieldName ")"
rule <k> @deparseField(I:InstanceName,F:FieldName) => @packetOut(V /*@FieldVal2String(V,@getAttr(F,Fs))*/) ...</k>
         <instances>
             <instance> <name> I </name> <typeName> H:HeaderTypeName </typeName> <fieldVals> F |-> V:Val ...</fieldVals> ... </instance>
             ...
         </instances>
//         <headers>
//            <header> <name> H </name> <fields> Fs:FieldDecs </fields> ... </header>
//            ...
//         </headers>


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


syntax Val ::= "@concat" "(" Vals ")" [function]

rule @concat(@cons(V:Val,@nil)) => V
//todo: complete this



//TODO:temporary, maybe we want to resolve the referece to header first
//If not, complete it is for array
syntax KItem /* Val */ ::= "@readField" "(" K /* FieldRef */ ")"
rule <k> @readField(H:InstanceName . F:FieldName) => V ... </k>
      <instances>
         <instance> <name> H </name> <valid> true </valid> <fieldVals> F |-> V:Val ...</fieldVals> ...  </instance> ...
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
		 | K "%|"  K [seqstrict]

rule V1:Val %== V2:Val => V1 == V2
rule V1:Val %& V2:Val => V1 & V2
rule V1:Val %& V2:Val => V1 | V2
rule B1:Bool %&& B2:Bool => B1 andBool B2



//------------------const value--------------------------



syntax Vals ::= "@nil" | "@cons" "(" Val "," Vals ")"
syntax KResult ::= Val | Vals

syntax KItem /* Vals */ ::= "@makeCons" "(" K /* Val */ "," K /* Vals */ ")" [seqstrict]

rule @makeCons(V:Val,Vs:Vals) => @cons (V,Vs)


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



//----------------------------temporary utils----------------------------------







endmodule
