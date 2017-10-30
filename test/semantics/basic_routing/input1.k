     <tables>
        ...
        <table>
            ...
            <name> port_mapping </name>
            <rules> .List   => (
                                 ListItem(
                                    $rule(0,
                                        $ctr(ListItem(@val ( 1 , 0 , false )))
                                    , @call(String2Id("set_bd") , $resolved( ListItem(@val(10,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(1,
                                        $ctr(ListItem(@val ( 2 , 0 , false )))
                                    , @call(String2Id("set_bd") , $resolved( ListItem(@val(10,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(2,
                                        $ctr(ListItem(@val ( 3 , 0 , false )))
                                    , @call(String2Id("set_bd") , $resolved( ListItem(@val(20,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(3,
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
                                    $rule(4,
                                        $ctr(ListItem(@val ( 10 , 0 , false )))
                                    , @call(String2Id("set_vrf") , $resolved( ListItem(@val(30,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(5,
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
                                    $rule(6,
                                                                                               //192.168.0.0
                                        $ctr(ListItem(@val ( 30 , 0 , false )) ListItem(@val ( 3232235520 , 0 , false )))
                                    , @call(String2Id("fib_hit_nexthop") , $resolved( ListItem(@val(1,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(7,
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
                                    $rule(8,
                                        $ctr(ListItem(@val ( 1 , 0 , false )) )
                                    , @call(String2Id("set_egress_details") , $resolved( ListItem(@val(1,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(9,
                                        $ctr(ListItem(@val ( 2 , 0 , false )) )
                                    , @call(String2Id("set_egress_details") , $resolved( ListItem(@val(2,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(10,
                                        $ctr(ListItem(@val ( 3 , 0 , false )) )
                                    , @call(String2Id("set_egress_details") , $resolved( ListItem(@val(3,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(11,
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
                                    $rule(12,
                                        $ctr(ListItem(@val ( 1 , 0 , false )) )
                                                                                          //01:01:01:01:01:01                   //00:01:01:01:01:01
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1103823438081,0,false)) ListItem(@val(4311810305,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(13,
                                        $ctr(ListItem(@val ( 2 , 0 , false )) )
                                                                                          //01:02:02:02:02:02                   //00:02:02:02:02:02
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1108135248386,0,false)) ListItem(@val(8623620610,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(14,
                                        $ctr(ListItem(@val ( 3 , 0 , false )) )
                                                                                          //01:03:03:03:03:03                   //00:03:03:03:03:03
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1112447058691,0,false)) ListItem(@val(12935430915,0,false)) ) ))
                                 )
                                 ListItem(
                                    $rule(15,
                                        $ctr(ListItem(@val ( 4 , 0 , false )) )
                                                                                          //01:04:04:04:04:04                   //00:04:04:04:04:04
                                    , @call(String2Id("rewrite_src_dst_mac") , $resolved( ListItem(@val(1116758868996,0,false)) ListItem(@val(17247241220,0,false)) ) ))
                                 )
                             )
            </rules>
        </table>
        ...
     </tables>
                    //00:00:00:00:00:01 00:00:00:00:00:00   ....  TTL:64 .... 10.0.0.1 10.0.0.0
                    //0000 0000 0001 0000 0000 0000 0800 4500 0044 ad0b 0000 4011 7272 0a00 0001 0a00 0000
     //<packet> . => "00000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000001000000000000100010100000000000000000100010010101101000010110000000000000000010000000001000101110010011100100000101000000000000000000000000100001010000000000000000000000000" </packet>
     <buffer>
     <in> .List => ListItem($packet(
                   ListItem(@val(1,48,false)) //dst mac
                   ListItem(@val(0,48,false)) //src mac
                   ListItem(@val(2048,16,false)) //ethertype
                   ListItem(@val(4,4,false)) //ip version
                   ListItem(@val(20,4,false)) //ihl
                   ListItem(@val(0,8,false)) //diffserv
                   ListItem(@val(68,16,false)) //total len
                   ListItem(@val(44299,16,false)) //id
                   ListItem(@val(0,3,false)) //flags
                   ListItem(@val(0,13,false)) //frag offset
                   ListItem(@val(64,8,false)) //ttl
                   ListItem(@val(17,8,false)) //protocol
                   ListItem(@val(7272,16,false)) //checksum
                   ListItem(@val(167772161,32,false)) //src ip
                   ListItem(@val(167772160,32,false)) //dst ip
                   , 1 //port
                   ))
     </in>
     ...
     </buffer>

syntax Id ::=      "port_mapping" [token]
                 | "bd"           [token]
	             | "ipv4_fib"     [token]
	             | "nexthop"      [token]
	             | "rewrite_mac"  [token]