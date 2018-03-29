
module IMPP-SPEC
  imports IMPP

syntax Id ::= "h_t" [token] | "h1_f1" [token] | "h1_f2" [token] | "h1_valid" [token]
            |  "ingress" [token] | "t" [token] | "a" [token] | "b" [token] | "start" [token]
            | "parse" [token] | "apply_t" [token] | "process_packet" [token] | "deparse" [token] | "index" [token] | "n" [token]



rule
<L2>
   <k>main ( .Args ) ;</k>
   <state>h1_f1 |-> 0 h1_f2 |-> 0 h1_valid |-> false standard_metadata_egress_spec |-> 0</state>
   <funs>
      start |-> $fun ( .Params , { if ( ! ( #has_next ( 8 , .Args ) ) ) { h1_valid = ! (! h1_valid); return false ; } h1_f1 = #extract_next ( 8 , ( false , .Args ) ) ; if ( ! ( #has_next ( 8 , .Args ) ) ) { return false ; } h1_f2 = #extract_next ( 8 , ( false , .Args ) ) ; h1_valid = true ; return true ; } )
      apply_t |-> $fun ( .Params , { while ( #get_next_enrty ( .Args ) ) { if ( #entry_matches ( h1_f1 , .Args ) ) { #call_entry_action ( .Args ) ; return 0 ; } } if ( #has_default_action ( .Args ) ) { #call_default_action ( .Args ) ; } } )
      parse |-> $fun ( .Params , { return start ( .Args ) ; } )
      b |-> $fun ( .Params , { standard_metadata_egress_spec = 2 ; } )
      process_packet |-> $fun ( .Params , { #reset ( .Args ) ; standard_metadata_egress_spec = -1 ; h1_valid = false ; if ( ! ( parse ( .Args ) ) ) { return false ; } apply_t ( .Args ) ; if ( standard_metadata_egress_spec == -1 ) { return false ; } return true ; } )
      a |-> $fun ( ( int n ) , .Params , { h1_f2 = n ; standard_metadata_egress_spec = 1 ; } )
      deparse |-> $fun ( .Params , { if ( h1_valid ) { #emit ( h1_f1 , ( 8 , ( false , .Args ) ) ) ; ( #emit ( h1_f2 , ( 8 , ( false , .Args ) ) ) ) ; } } )
      main |-> $fun ( .Params , { while ( #get_next_packet ( .Args ) ) { if ( ! ( process_packet ( .Args ) ) ) { #drop ( .Args ) ; } else { deparse ( .Args ) ; ( #output_packet ( .Args ) ) ; } } } )
   </funs>
   <stack>.List</stack>
   <in>  I:PacketList </in>
   <out>$nilPacketList</out>
   <packet>@nil</packet>
   <packetout>@nil</packetout>
   <table>T:EntryList</table>
   <crntE>$nilEntryList</crntE>
   <ce>_</ce>
   <index>0</index>
   <default> D:DefaultEntry </default>
</L2>
requires #wellDefTable(T) andBool #wellDefDefaultAction(D)
ensures vars(ListItem(I) ListItem(T) ListItem(D))
//ensures vars(ListItem(T) ListItem(0))

rule
<L2>
   <k> #get_next_packet ( .Args ) ~> `#freezerif(_)_else_1` ( { { if ( ! ( process_packet ( .Args ) ) ) { #drop ( .Args ) ; } else { deparse ( .Args ) ; ( #output_packet ( .Args ) ) ; } } while ( #get_next_packet ( .Args ) ) { if ( ! ( process_packet ( .Args ) ) ) { #drop ( .Args ) ; } else { deparse ( .Args ) ; ( #output_packet ( .Args ) ) ; } } } , { } ) ~> return 0 ; </k>
   <state>h1_f1 |-> _:Int h1_f2 |-> _:IVal h1_valid |-> _:Bool standard_metadata_egress_spec |-> _:Int</state>
   <funs>
      start |-> $fun ( .Params , { if ( ! ( #has_next ( 8 , .Args ) ) ) { h1_valid = ! (! h1_valid); return false ; } h1_f1 = #extract_next ( 8 , ( false , .Args ) ) ; if ( ! ( #has_next ( 8 , .Args ) ) ) { return false ; } h1_f2 = #extract_next ( 8 , ( false , .Args ) ) ; h1_valid = true ; return true ; } )
      apply_t |-> $fun ( .Params , { while ( #get_next_enrty ( .Args ) ) { if ( #entry_matches ( h1_f1 , .Args ) ) { #call_entry_action ( .Args ) ; return 0 ; } } if ( #has_default_action ( .Args ) ) { #call_default_action ( .Args ) ; } } )
      parse |-> $fun ( .Params , { return start ( .Args ) ; } )
      b |-> $fun ( .Params , { standard_metadata_egress_spec = 2 ; } )
      process_packet |-> $fun ( .Params , { #reset ( .Args ) ; standard_metadata_egress_spec = -1 ; h1_valid = false ; if ( ! ( parse ( .Args ) ) ) { return false ; } apply_t ( .Args ) ; if ( standard_metadata_egress_spec == -1 ) { return false ; } return true ; } )
      a |-> $fun ( ( int n ) , .Params , { h1_f2 = n ; standard_metadata_egress_spec = 1 ; } )
      deparse |-> $fun ( .Params , { if ( h1_valid ) { #emit ( h1_f1 , ( 8 , ( false , .Args ) ) ) ; ( #emit ( h1_f2 , ( 8 , ( false , .Args ) ) ) ) ; } } )
      main |-> $fun ( .Params , { while ( #get_next_packet ( .Args ) ) { if ( ! ( process_packet ( .Args ) ) ) { #drop ( .Args ) ; } else { deparse ( .Args ) ; ( #output_packet ( .Args ) ) ; } } } )
   </funs>
   <stack> ListItem ( $cnt ( .Params , `#freezer_;0` ( .KList ) ) ) </stack>
   <in>  I:PacketList </in>
   <out> O:PacketList </out>
   <packet>_</packet>
   <packetout>_</packetout>
   <table>T:EntryList</table>
   <crntE>_</crntE>
   <ce>_</ce>
   <index>_</index>
   <default> D:DefaultEntry </default>
</L2>
requires #wellDefTable(T) andBool #wellDefDefaultAction(D)
ensures vars(ListItem(T) ListItem(I) ListItem(O) ListItem(D))

rule
<L2>
   <k> #get_next_enrty ( .Args ) ~> `#freezerif(_)_else_1` ( { { if ( #entry_matches ( h1_f1 , .Args ) ) { #call_entry_action ( .Args ) ; return 0 ; } } while ( #get_next_enrty ( .Args ) ) { if ( #entry_matches ( h1_f1 , .Args ) ) { #call_entry_action ( .Args ) ; return 0 ; } } } , { } ) ~> ( if ( #has_default_action ( .Args ) ) { #call_default_action ( .Args ) ; } ) ~> return 0 ; </k>
   <state>h1_f1 |-> F1:Int h1_f2 |-> F2:IVal h1_valid |-> Valid:Bool standard_metadata_egress_spec |-> E:Int</state>
   <funs>
      start |-> $fun ( .Params , { if ( ! ( #has_next ( 8 , .Args ) ) ) { h1_valid = ! (! h1_valid); return false ; } h1_f1 = #extract_next ( 8 , ( false , .Args ) ) ; if ( ! ( #has_next ( 8 , .Args ) ) ) { return false ; } h1_f2 = #extract_next ( 8 , ( false , .Args ) ) ; h1_valid = true ; return true ; } )
      apply_t |-> $fun ( .Params , { while ( #get_next_enrty ( .Args ) ) { if ( #entry_matches ( h1_f1 , .Args ) ) { #call_entry_action ( .Args ) ; return 0 ; } } if ( #has_default_action ( .Args ) ) { #call_default_action ( .Args ) ; } } )
      parse |-> $fun ( .Params , { return start ( .Args ) ; } )
      b |-> $fun ( .Params , { standard_metadata_egress_spec = 2 ; } )
      process_packet |-> $fun ( .Params , { #reset ( .Args ) ; standard_metadata_egress_spec = -1 ; h1_valid = false ; if ( ! ( parse ( .Args ) ) ) { return false ; } apply_t ( .Args ) ; if ( standard_metadata_egress_spec == -1 ) { return false ; } return true ; } )
      a |-> $fun ( ( int n ) , .Params , { h1_f2 = n ; standard_metadata_egress_spec = 1 ; } )
      deparse |-> $fun ( .Params , { if ( h1_valid ) { #emit ( h1_f1 , ( 8 , ( false , .Args ) ) ) ; ( #emit ( h1_f2 , ( 8 , ( false , .Args ) ) ) ) ; } } )
      main |-> $fun ( .Params , { while ( #get_next_packet ( .Args ) ) { if ( ! ( process_packet ( .Args ) ) ) { #drop ( .Args ) ; } else { deparse ( .Args ) ; ( #output_packet ( .Args ) ) ; } } } )
   </funs>
   <stack> ListItem ( $cnt ( .Params , `#freezer_;0` ( .KList ) ~> ( if ( standard_metadata_egress_spec == -1 ) { return false ; } ) ~> return true ; ~> return 0 ; ) ) ListItem ( $cnt ( .Params , `#freezer!_0` ( .KList ) ~> `#freezerif(_)_else_1` ( { #drop ( .Args ) ; } , { deparse ( .Args ) ; ( #output_packet ( .Args ) ) ; } ) ~> ( while ( #get_next_packet ( .Args ) ) { if ( ! ( process_packet ( .Args ) ) ) { #drop ( .Args ) ; } else { deparse ( .Args ) ; ( #output_packet ( .Args ) ) ; } } ) ~> return 0 ; ) ) ListItem ( $cnt ( .Params , `#freezer_;0` ( .KList ) ) ) </stack>
   <in>  I:PacketList </in>
   <out> O:PacketList </out>
   <packet>_</packet>
   <packetout>PO:Vals</packetout>  //need to say packet out so far is the same
   <table>T:EntryList</table>
   <crntE>C:EntryList</crntE>
   <ce>_</ce>
   <index>_</index>
   <default> D:DefaultEntry </default>
</L2>
//ensures vars(ListItem(L) ListItem(T))
requires #wellDefTable(T) andBool #wellDefDefaultAction(D) andBool #wellDefTable(C)
ensures vars(ListItem(I) ListItem(O) ListItem(T) ListItem(C) ListItem(F1) ListItem(F2) ListItem(Valid) ListItem(E) ListItem(PO) ListItem(D))
//*** CE should not be the same
//converted #freezer... to `#freezer...` also () to (.KList)

rule
<L2>
   <k> .K </k>
   <state>h1_f1 |-> _ h1_f2 |-> _ h1_valid |-> _ standard_metadata_egress_spec |-> _</state>
   <funs>
      start |-> $fun ( .Params , { if ( ! ( #has_next ( 8 , .Args ) ) ) { h1_valid = ! (! h1_valid); return false ; } h1_f1 = #extract_next ( 8 , ( false , .Args ) ) ; if ( ! ( #has_next ( 8 , .Args ) ) ) { return false ; } h1_f2 = #extract_next ( 8 , ( false , .Args ) ) ; h1_valid = true ; return true ; } )
      apply_t |-> $fun ( .Params , { while ( #get_next_enrty ( .Args ) ) { if ( #entry_matches ( h1_f1 , .Args ) ) { #call_entry_action ( .Args ) ; return 0 ; } } if ( #has_default_action ( .Args ) ) { #call_default_action ( .Args ) ; } } )
      parse |-> $fun ( .Params , { return start ( .Args ) ; } )
      b |-> $fun ( .Params , { standard_metadata_egress_spec = 2 ; } )
      process_packet |-> $fun ( .Params , { #reset ( .Args ) ; standard_metadata_egress_spec = -1 ; h1_valid = false ; if ( ! ( parse ( .Args ) ) ) { return false ; } apply_t ( .Args ) ; if ( standard_metadata_egress_spec == -1 ) { return false ; } return true ; } )
      a |-> $fun ( ( int n ) , .Params , { h1_f2 = n ; standard_metadata_egress_spec = 1 ; } )
      deparse |-> $fun ( .Params , { if ( h1_valid ) { #emit ( h1_f1 , ( 8 , ( false , .Args ) ) ) ; ( #emit ( h1_f2 , ( 8 , ( false , .Args ) ) ) ) ; } } )
      main |-> $fun ( .Params , { while ( #get_next_packet ( .Args ) ) { if ( ! ( process_packet ( .Args ) ) ) { #drop ( .Args ) ; } else { deparse ( .Args ) ; ( #output_packet ( .Args ) ) ; } } } )
   </funs>
   <stack>.List</stack>
   <in> $nilPacketList </in>
   <out>O:PacketList</out>
   <packet>_</packet>
   <packetout>_</packetout>
   <table>_</table>
   <crntE>_</crntE>
   <ce>_</ce>
   <index>_</index>
   <default>_</default>
</L2>
ensures vars(ListItem(O) ListItem(0))
[trusted]
endmodule
