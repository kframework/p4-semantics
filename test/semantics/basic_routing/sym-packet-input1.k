     <tables>
        ...
        <table>
            ...
            <name> port_mapping </name>
            <rules> .List   => (
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 1 , 0 , false )))
                                    , @call(String2Id("set_bd") , $resolved( ListItem(@val(10,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 2 , 0 , false )))
                                    , @call(String2Id("set_bd") , $resolved( ListItem(@val(10,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 3 , 0 , false )))
                                    , @call(String2Id("set_bd") , $resolved( ListItem(@val(20,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 4 , 0 , false )))
                                    , @call(String2Id("set_bd") , $resolved( ListItem(@val(20,0,false)) ) ))
                                 )
                               )
            </rules>
        </table>
        <table>
            ...
            <name> bd </name>
            <rules> .List => (
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 10 , 0 , false )))
                                    , @call(String2Id("set_vrf") , $resolved( ListItem(@val(30,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 20 , 0 , false )))
                                    , @call(String2Id("set_vrf") , $resolved( ListItem(@val(30,0,false)) ) ))
                                 )
                             )
            </rules>
        </table>
        <table>
            ...
            <name> ipv4_fib </name>
            <rules> .List => (
                                 ListItem(
                                    $rule(
                                                                                               //192.168.0.0
                                        $ctr(ListItem(@val ( 30 , 0 , false )) ListItem(@val ( 3232235520 , 0 , false )))
                                    , @call(String2Id("fib_hit_nexthop") , $resolved( ListItem(@val(1,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                                                                               //10.0.0.0
                                        $ctr(ListItem(@val ( 30 , 0 , false )) ListItem(@val ( 167772160 , 0 , false )))
                                    , @call(String2Id("fib_hit_nexthop") , $resolved( ListItem(@val(3,0,false)) ) ))
                                 )
                             )
            </rules>
        </table>
        <table>
            ...
            <name> nexthop </name>
            <rules> .List => (
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 1 , 0 , false )) )
                                    , @call(String2Id("set_egress_details") , $resolved( ListItem(@val(1,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 2 , 0 , false )) )
                                    , @call(String2Id("set_egress_details") , $resolved( ListItem(@val(2,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 3 , 0 , false )) )
                                    , @call(String2Id("set_egress_details") , $resolved( ListItem(@val(3,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 4 , 0 , false )) )
                                    , @call(String2Id("set_egress_details") , $resolved( ListItem(@val(4,0,false)) ) ))
                                 )

                             )
            </rules>
        </table>
        <table>
            ...
            <name> rewrite_mac </name>
            <rules> .List => (
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 1 , 0 , false )) )
                                                                                          //01:01:01:01:01:01                   //00:01:01:01:01:01
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1103823438081,0,false)) ListItem(@val(4311810305,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 2 , 0 , false )) )
                                                                                          //01:02:02:02:02:02                   //00:02:02:02:02:02
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1108135248386,0,false)) ListItem(@val(8623620610,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 3 , 0 , false )) )
                                                                                          //01:03:03:03:03:03                   //00:03:03:03:03:03
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1112447058691,0,false)) ListItem(@val(12935430915,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 4 , 0 , false )) )
                                                                                          //01:04:04:04:04:04                   //00:04:04:04:04:04
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1116758868996,0,false)) ListItem(@val(17247241220,0,false)) ) ))
                                 )
                             )
            </rules>
        </table>
        ...
     </tables>

     <buffer> <in> .List => ListItem($packet(?P:List, 1)) </in> ... </buffer>
     //<packet> . => ?P:List </packet>
     //<packet> . => ?P:String </packet>

syntax Id ::=      "port_mapping" [token]
                 | "bd"           [token]
	             | "ipv4_fib"     [token]
	             | "nexthop"      [token]
	             | "rewrite_mac"  [token]