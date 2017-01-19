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
    <index>
        0
    </index>

    //<lastExtract>
    //    .K
    //</lastExtract>

</T>


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

rule <k> @processDec(metadata Type:HeaderTypeName Name:InstanceName { Asgn:FieldValueAssignments } ) => . ... </k>
    <instances>  (.Bag =>
        <instance>
             <valid> true </valid>
                <metadata> true </metadata> <typeName> Type </typeName> <name> Name </name> <fieldVals> @initFields(Asgn,@fieldSet(Fields,.Set),.Map) </fieldVals>  ...
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

syntax Set ::= "@fieldSet" "(" FieldDecs "," Set ")" [function]
rule @fieldSet(N:FieldName : _:BitWidth ( _:FieldMods ) ; Rest:FieldDecs, Acc:Set) => @fieldSet(Rest, SetItem(N) Acc)
rule @fieldSet(.FieldDecs, Acc:Set) => Acc
//TODO: ask if we can get rid of the Acc
//TODO: check a field is not decrlared twice


syntax Map ::= "@initFields" "(" FieldValueAssignments "," Set "," Map ")" [function]
rule @initFields(.FieldValueAssignments, .Set, Acc:Map) => Acc
rule @initFields(.FieldValueAssignments, SetItem(N:FieldName) Fields:Set, Acc:Map) =>
        @initFields(.FieldValueAssignments, Fields, N |-> #token("0","DecimalValueToken@VALUE-SYNTAX")  Acc)
//TODO: fix the token thing
rule @initFields(N:FieldName : V:FieldValue ; Rest:FieldValueAssignments, SetItem(N:FieldName) Fields:Set, Acc:Map) =>
        @initFields(Rest, Fields, N |-> V  Acc)

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
         ) ... </controlFlows>


// --------------------init------------------------------------

syntax KItem ::= "@init" | "@parse&ingress" | "@egress"

rule @exec => @init ~> @parse&ingress ~> @egress


//syntax Input ::= "packet" "(" String ")"

//syntax Packet ::= "packet" "(" Int ")"

//syntax Rule ::= "$rule" "(" Criteria  ","  ActionName ")"
//syntax Criteria ::= "$ctr" "(" Matchs ")"
//syntax Matchs ::= List{Match,","} [klable('Matchs)]
//syntax Match ::= FieldOrMaskedRef ":" ConstValue //TODO:complete this

syntax Rule ::= "$rule" "(" Criteria "," ActionName ")"
syntax Criteria ::= "$ctr" "(" List ")"

//temporary
syntax Id ::= "egress_meter" [token]
rule <k> @init => . ... </k>
     <packet> . => "0010000101010101000100001010101010001000010101010100010000101010101000100001010101010" </packet>
     <tables>
        ...
        <table>
            ...
            <name> egress_meter </name>
            <rules> .List => ListItem(
                                $rule(
                                    $ctr(ListItem( @val ( 279611477 , 48 , false )))
                                , String2Id("meter_pkt")  )
                            )</rules>
        </table>
        ...
     </tables>



//--------------------parsing------------------------------
syntax Id ::= "start" [token]
rule <k> @parse&ingress => Body  ... </k>
     <parserStates> <state>  <name> start </name> <body> Body </body> ... </state> ...</parserStates>

rule ESs:ExtractOrSetStatements R:ReturnStatement => ESs ~> R           [structural]
rule ES:ExtractOrSetStatement ESs:ExtractOrSetStatements => ES ~> ESs   [structural]

rule .ExtractOrSetStatements => .

//return to state
//TODO: check it is not control function name
rule <k> return State:ParserStateName ; => Body ... </k>
     <parserStates> <state>  <name> State </name> <body> Body </body> ... </state> ...</parserStates>

//return to control function
rule <k> return Control:ControlFunctionName ; => Control(); ... </k>


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
    => @if @concat(Vs) ==== @concat(Vss)  @then @caseReturnToReturn(CA) @else @select(Vs,Rest)  //TODO: change this to == in Val when we have complete semantics for it

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
//TODO <k> rule @readFDRefs(latest . FN:FieldName , Rest:FieldOrDataRefs) =>  @makeCons(@readField(H.F),@readVals(Rest)) ... </k>
//        <lastExtract> I:HeaderInstanceName </lastExtract>
//TODO rule @readVals(current())




//extract
rule <k> extract (Name:InstanceName) ;  => @extract(Name,Fields) ... </k>
     <instances>
        <instance> <name> Name </name> <metadata> false </metadata> <typeName> Type:HeaderTypeName </typeName> ... </instance> ...
     </instances>
     <headers>
        <header> <name> Type </name>  <fields> Fields:FieldDecs </fields> ... </header> ...
     </headers>
//TODO: what happens if a valid header gets extracted again?

syntax KItem ::= "@extract" "(" InstanceName "," FieldDecs ")"
rule <k> @extract(N:InstanceName, .FieldDecs) => . ... </k>
     <instances>
            <instance> <name> N </name>  <valid> false => true </valid> ... </instance> ...
     </instances>

rule @extract(N:InstanceName, F:FieldName : CW:ConstValue ( _:FieldMods ) ; Rest:FieldDecs ) =>
        @extractField(N,F,CW) ~> @extract(N,Rest)

syntax KItem ::= "@extractField" "(" InstanceName "," FieldName "," K /* Val */ ")" [strict(3)]
rule <k> @extractField(N:InstanceName, F:FieldName , W:Val ) => . ... </k>
     <instances>
        <instance> <name> N </name> <fieldVals>  (.Map => (F |-> @val(String2Base(substrString(Packet,I,Val2Int(W)),2),Val2Int(W),false))) ... </fieldVals> ... </instance>
        ...
     </instances>
     <packet> Packet </packet>
     <index> I:Int => I +Int Val2Int(W) </index>
//TODO: the sign should be extracted according to field_mod more imporantly the Int should be change according to the sign */
//TODO: support *
//TODO: change the string to number value
//TODO: add _:Map to <fieldVals>

//TODO: array


//----------------control flow-------------------------
rule .ControlStatements => .                                [structural] //TODO: maybe add a default action
rule S:ControlStatement Rest:ControlStatements => S ~> Rest [structural]
rule { B:ControlStatement } => B                            [structural]

//apply
rule apply (T:TableName) ; => apply (T) { .HitMissCases }   [macro]


//for now assuming that a screenshot of current rules are taken before matching
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

rule @val(V1,W1,S1) == @val(V2,W2,S2) => V1 ==Int V2 //TODO: complete this
//TODO: > >= <= <= < !=
//TODO: + * - << >> & | ^
//TODO: ^ -
rule B1:Bool or B2:Bool => B1 orBool B2
rule B1:Bool and B2:Bool => B1 andBool B2
//TODO: short circuit ?

//---------------table match-----------------------------
syntax KItem ::= "@checkNextRule" "(" FieldMatchs "," List /*rules*/ ")"

//TODO: check defualt action
//TODO: what else todo
//TODO: assumming rules are checked for consistency at the time of insertion and are  are sorted by their priority


syntax ActionName ::= "@miss" [token]
rule @checkNextRule(_:FieldMatchs,.List  ) => @miss
rule @checkNextRule(FM:FieldMatchs, ListItem($rule($ctr(R:List),A:ActionName)) Rest:List)
    => @if @matchAll(FM,R) @then @call(A) ~> A  @else @checkNextRule(FM,Rest)

syntax KItem /* Bool */ ::= "@matchAll" "(" FieldMatchs "," List /*criteria*/  ")"
rule @matchAll(.FieldMatchs,.List) => true
rule @matchAll(FMR:FieldOrMaskedRef : MT:FieldMatchType ; R1:FieldMatchs, ListItem(V:K) R2:List)
    => @match(@readFMRef(FMR),V,MT) =&&= @matchAll(R1,R2) //TODO change it with &&

syntax KItem /* Bool */ ::= "@match" "(" K /* KResult */ "," K /* KResult */ "," FieldMatchType  ")" [strict(1,2)]
rule @match(@val(V1,W1,S1),@val(V2,W2,S2),exact) =>
    (V1 ==Int V2) andBool (W1 ==Int W2) andBool (S1 ==Bool S2) //TODO: it this it?
//TODO: rule @match(V:?,M:?,ternary)
//TODO: rule @match(V:?,M:?,lmp)
//TODO: rule @match(V:?,M:?,range)
//TODO: rule @match(V:?,M:?,valid)


syntax KItem /* KResult */ ::= "@readFMRef" "(" FieldOrMaskedRef ")"
//rule @readFMRef(H:HeaderRef) => //TODO
rule @readFMRef(F:FieldRef) => @readField(F)
rule @readFMRef(F:FieldRef mask M:ConstValue)  => @applyMask(@readField(F),M)





//---------------actions----------------------------------
syntax KItem ::= "@call" "(" ActionName ")"

//TODO temporary
rule @call( _ ) => .


//----------------header and field ref--------------------
//syntax HRef ::= "@href" "(" HeaderInstanceName ")"
//syntax FieldRef ::= HRef "." FieldName
//syntax KResult ::= HRef
//
//rule HI:HeaderInstanceName => @href(HI)
//TODO: support array
//TODO:maybe @href is not needed, instance name is enough




//------------------utils-------------------------------
syntax Int ::= "Val2Int" "(" Val ")" [function]
rule Val2Int ( @val(I:Int,_,_) ) => I


syntax Id ::= BinaryValueToken | DecimalValueToken | HexadecimalValueToken
syntax Int ::= "USgnVal2Int" "(" ConstValue ")" [function]
//TODO: change all letters to lower caseste
rule USgnVal2Int( UV:BinaryValueToken ) => String2Base(replaceFirst(replaceAll(Id2String(UV),"_",""),"0b",""),2)
rule USgnVal2Int( UV:DecimalValueToken ) => String2Int(replaceAll(Id2String(UV),"_",""))
rule USgnVal2Int( UV:HexadecimalValueToken ) => String2Base(replaceFirst(replaceAll(Id2String(UV),"_",""),"0x",""),16)


syntax K ::= "@if" K /* Bool */ "@then" K "@else" K [strict(1)]
syntax KResult ::= Bool
rule @if true @then T:K @else F:K => T
rule @if false @then T:K @else F:K => F




syntax Val ::= "@concat" "(" Vals ")" [function]

rule @concat(@cons(V:Val,@nil)) => V
//todo: complete this



//TODO:temporary, maybe we want to resolve the referece to header first
//If not, complete it is for array
syntax KItem /* Val */ ::= "@readField" "(" K /* FieldRef */ ")"
rule <k> @readField(H:HeaderInstanceName . F:FieldName) => V ... </k>
      <instances>
         <instance> <name> H </name>  <fieldVals> F |-> V:Val ...</fieldVals> ...  </instance> ...
      </instances>


syntax KItem /* Val */ ::= "@applyMask" "(" K /* Val */ "," K /* Val */ ")" [strict]


//------------------const value--------------------------


syntax Val ::= "@val" "("Int","Int","Bool")" //int,width,signed
syntax Vals ::= "@nil" | "@cons" "(" Val "," Vals ")"
syntax KResult ::= Val | Vals

syntax KItem /* Vals */ ::= "@makeCons" "(" K /* Val */ "," K /* Vals */ ")" [seqstrict]

rule @makeCons(V:Val,Vs:Vals) => @cons (V,Vs)




//rule T:BinaryValueToken => #parseToken(replaceAll(Id2String(T)),"BinaryValueToken") [macro]
//TODO is it possible to do so?


rule UV:UnsignedValue => @val(USgnVal2Int(UV),0,false)
//rule (+ @val(N:Int,0,false)) => @val(N,0,false)
//rule (- @val(N:Int,0,false)) => @val(N,0,true)
//rule (+ W:DecimalValueToken' @val(N:Int,0,false)) => (W' @val(N:Int,0,false))
//rule (W:DecimalValueToken' @val(N:Int,0,false)) => @val(USgnVal2Int(W))
//rule (- W:DecimalValueToken' @val(N:Int,0,false)) => @val(USgnVal2Int(W))



//----------------------------temporary utils----------------------------------


syntax KItem ::= K "====" K [seqstrict]
rule (@val(V:Int,0,S:Bool) ==== @val(V,0,S)) => true
rule (V1:Val ==== V2:Val) => false  [owise]

syntax KItem ::= K "=&&=" K [seqstrict]
rule B1:Bool =&&= B2:Bool => B1 andBool B2




endmodule