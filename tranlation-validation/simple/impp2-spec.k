
module IMPP-SPEC
  imports IMPP

syntax Id ::= "h_t" [token] | "h1_f1" [token] | "h1_f2" [token] | "h1_valid" [token]
            |  "ingress" [token] | "t" [token] | "a" [token] | "b" [token] | "start" [token]
            | "parse" [token] | "apply_t" [token] | "process_packet" [token] | "deparse" [token] | "index" [token] | "n" [token]

//rule
//<L2>
//   <k>main ( .Args ) ;</k>
//   <state>h1_f1 |-> 0 h1_f2 |-> 0 h1_valid |-> false standard_metadata_egress_spec |-> 0</state>
//   <funs>
//      start |-> $fun ( .Params , { if ( ! ( #has_next ( 8 , .Args ) ) ) { return false ; } h1_f1 = #extract_next ( 8 , ( false , .Args ) ) ; if ( ! ( #has_next ( 8 , .Args ) ) ) { return false ; } h1_f2 = #extract_next ( 8 , ( false , .Args ) ) ; h1_valid = true ; return true ; } )
//      apply_t |-> $fun ( .Params , { while ( #get_next_enrty ( .Args ) ) { if ( #entry_matches ( h1_f1 , .Args ) ) { #call_entry_action ( .Args ) ; return 0 ; } } } )
//      parse |-> $fun ( .Params , { return start ( .Args ) ; } )
//      b |-> $fun ( .Params , { standard_metadata_egress_spec = 2 ; } )
//      process_packet |-> $fun ( .Params , { #reset ( .Args ) ; standard_metadata_egress_spec = -1 ; h1_valid = false ; if ( ! ( parse ( .Args ) ) ) { return false ; } if ( standard_metadata_egress_spec == -1 ) { return false ; } return true ; } )
//      a |-> $fun ( ( int n ) , .Params , { h1_f2 = n ; standard_metadata_egress_spec = 1 ; } )
//      deparse |-> $fun ( .Params , { if ( h1_valid ) { #emit ( h1_f1 , .Args ) ; ( #emit ( h1_f2 , .Args ) ) ; } } )
//      main |-> $fun ( .Params , { while ( #get_next_packet ( .Args ) ) { if ( ! ( process_packet ( .Args ) ) ) { #drop ( .Args ) ; } else { deparse ( .Args ) ; ( #output_packet ( .Args ) ) ; } } } )
//   </funs>
//   <stack>.List</stack>
//   <in> L:PacketList </in>
//   <out>$nilPacketList</out>
//   <packet>.List</packet>
//   <packetout>.List</packetout>
//   <table>T:List</table>
//   <crntE>.List</crntE>
//   <index>0</index>
//</L2>
//ensures vars(ListItem(L) ListItem(T))
//[trusted]

rule
<L2>
   <k>main ( .Args ) ;</k>
   <state>h1_f1 |-> 0 h1_f2 |-> 0 h1_valid |-> false standard_metadata_egress_spec |-> 0</state>
   <funs>
      start |-> $fun ( .Params , { if ( ! ( #has_next ( 8 , .Args ) ) ) { h1_valid = ! (! h1_valid); return false ; } h1_f1 = #extract_next ( 8 , ( false , .Args ) ) ; if ( ! ( #has_next ( 8 , .Args ) ) ) { return false ; } h1_f2 = #extract_next ( 8 , ( false , .Args ) ) ; h1_valid = true ; return true ; } )
      apply_t |-> $fun ( .Params , { while ( #get_next_enrty ( .Args ) ) { if ( #entry_matches ( h1_f1 , .Args ) ) { #call_entry_action ( .Args ) ; return 0 ; } } } )
      parse |-> $fun ( .Params , { return start ( .Args ) ; } )
      b |-> $fun ( .Params , { standard_metadata_egress_spec = 2 ; } )
      process_packet |-> $fun ( .Params , { #reset ( .Args ) ; standard_metadata_egress_spec = -1 ; h1_valid = false ; if ( ! ( parse ( .Args ) ) ) { return false ; } apply_t ( .Args ) ; if ( standard_metadata_egress_spec == -1 ) { return false ; } return true ; } )
      a |-> $fun ( ( int n ) , .Params , { h1_f2 = n ; standard_metadata_egress_spec = 1 ; } )
      deparse |-> $fun ( .Params , { if ( h1_valid ) { #emit ( h1_f1 , ( 8 , ( false , .Args ) ) ) ; ( #emit ( h1_f2 , ( 8 , ( false , .Args ) ) ) ) ; } } )
      main |-> $fun ( .Params , { while ( #get_next_packet ( .Args ) ) { if ( ! ( process_packet ( .Args ) ) ) { #drop ( .Args ) ; } else { deparse ( .Args ) ; ( #output_packet ( .Args ) ) ; } } } )
   </funs>
   <stack>.List</stack>
   //<in>  $consPacketList($packet(ListItem(@val(0,8,false)) ListItem(@val(0,8,false)), 30), $nilPacketList) </in>
   <in> $nilPacketList </in>
   <out>$nilPacketList</out>
   <packet>.List</packet>
   <packetout>.List</packetout>
   <table>T:List</table>
   <crntE>.List</crntE>
   <index>0</index>
</L2>
//ensures vars(ListItem(L) ListItem(T))
ensures vars(ListItem(T) ListItem(0))


rule
<L2>
   <k> .K </k>
   <state>h1_f1 |-> _ h1_f2 |-> _ h1_valid |-> _ standard_metadata_egress_spec |-> _</state>
   <funs>
      start |-> $fun ( .Params , { if ( ! ( #has_next ( 8 , .Args ) ) ) { h1_valid = ! (! h1_valid); return false ; } h1_f1 = #extract_next ( 8 , ( false , .Args ) ) ; if ( ! ( #has_next ( 8 , .Args ) ) ) { return false ; } h1_f2 = #extract_next ( 8 , ( false , .Args ) ) ; h1_valid = true ; return true ; } )
      apply_t |-> $fun ( .Params , { while ( #get_next_enrty ( .Args ) ) { if ( #entry_matches ( h1_f1 , .Args ) ) { #call_entry_action ( .Args ) ; return 0 ; } } } )
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
   <table>_:List</table>
   <crntE>_</crntE>
   <index>_</index>
</L2>
ensures vars(ListItem(O) ListItem(0))
[trusted]
endmodule
