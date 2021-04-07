
<tables>
    ...

    <table>
        ...
        <t-name> bd </t-name>
        <rules> .List => 
        ListItem($rule(4,
                    $ctr(
                        ListItem(@val(10,0,false))
                    ),
                    @call(
                      String2Id("set_vrf"),
                      $resolved(
                        ListItem(@val(30,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(5,
                    $ctr(
                        ListItem(@val(20,0,false))
                    ),
                    @call(
                      String2Id("set_vrf"),
                      $resolved(
                        ListItem(@val(30,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => .K </default>
    </table>
        
    <table>
        ...
        <t-name> port_mapping </t-name>
        <rules> .List => 
        ListItem($rule(0,
                    $ctr(
                        ListItem(@val(1,0,false))
                    ),
                    @call(
                      String2Id("set_bd"),
                      $resolved(
                        ListItem(@val(10,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(1,
                    $ctr(
                        ListItem(@val(2,0,false))
                    ),
                    @call(
                      String2Id("set_bd"),
                      $resolved(
                        ListItem(@val(10,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(2,
                    $ctr(
                        ListItem(@val(3,0,false))
                    ),
                    @call(
                      String2Id("set_bd"),
                      $resolved(
                        ListItem(@val(20,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(3,
                    $ctr(
                        ListItem(@val(4,0,false))
                    ),
                    @call(
                      String2Id("set_bd"),
                      $resolved(
                        ListItem(@val(20,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => .K </default>
    </table>
        
    <table>
        ...
        <t-name> ipv4_fib_lpm </t-name>
        <rules> .List => 
        ListItem($rule(6,
                    $ctr(
                        ListItem(@val(30,0,false)) ListItem($pair(@val(3232235520,32,false),@val(4294901760,32,false)))
                    ),
                    @call(
                      String2Id("fib_hit_nexthop"),
                      $resolved(
                        ListItem(@val(1,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(7,
                    $ctr(
                        ListItem(@val(30,0,false)) ListItem($pair(@val(167772160,32,false),@val(4278190080,32,false)))
                    ),
                    @call(
                      String2Id("fib_hit_nexthop"),
                      $resolved(
                        ListItem(@val(3,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => 
            @call(
              String2Id("on_miss"),
              $resolved(
                .List
              )
            )
         </default>
    </table>
        
    <table>
        ...
        <t-name> ipv4_fib </t-name>
        <rules> .List => .List </rules>
        <default> .K => 
            @call(
              String2Id("on_miss"),
              $resolved(
                .List
              )
            )
         </default>
    </table>
        
    <table>
        ...
        <t-name> nexthop </t-name>
        <rules> .List => 
        ListItem($rule(8,
                    $ctr(
                        ListItem(@val(1,0,false))
                    ),
                    @call(
                      String2Id("set_egress_details"),
                      $resolved(
                        ListItem(@val(1,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(10,
                    $ctr(
                        ListItem(@val(2,0,false))
                    ),
                    @call(
                      String2Id("set_egress_details"),
                      $resolved(
                        ListItem(@val(2,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(12,
                    $ctr(
                        ListItem(@val(3,0,false))
                    ),
                    @call(
                      String2Id("set_egress_details"),
                      $resolved(
                        ListItem(@val(3,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(14,
                    $ctr(
                        ListItem(@val(4,0,false))
                    ),
                    @call(
                      String2Id("set_egress_details"),
                      $resolved(
                        ListItem(@val(4,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => 
            @call(
              String2Id("on_miss"),
              $resolved(
                .List
              )
            )
         </default>
    </table>
        
    <table>
        ...
        <t-name> rewrite_mac </t-name>
        <rules> .List => 
        ListItem($rule(9,
                    $ctr(
                        ListItem(@val(1,0,false))
                    ),
                    @call(
                      String2Id("rewrite_src_dst_mac"),
                      $resolved(
                        ListItem(@val(1103823438081,0,false)) ListItem(@val(4311810305,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(11,
                    $ctr(
                        ListItem(@val(2,0,false))
                    ),
                    @call(
                      String2Id("rewrite_src_dst_mac"),
                      $resolved(
                        ListItem(@val(1108135248386,0,false)) ListItem(@val(8623620610,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(13,
                    $ctr(
                        ListItem(@val(3,0,false))
                    ),
                    @call(
                      String2Id("rewrite_src_dst_mac"),
                      $resolved(
                        ListItem(@val(1112447058691,0,false)) ListItem(@val(12935430915,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(15,
                    $ctr(
                        ListItem(@val(4,0,false))
                    ),
                    @call(
                      String2Id("rewrite_src_dst_mac"),
                      $resolved(
                        ListItem(@val(1116758868996,0,false)) ListItem(@val(17247241220,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => 
            @call(
              String2Id("on_miss"),
              $resolved(
                .List
              )
            )
         </default>
    </table>
        
</tables>

<in> .List =>
        ListItem($packet("10101010101010101010101010101010101010101010101010111011101110111011101110111011101110111011101100001000000000000100010100000000000000000010110000000000000000000000000001100101010000000001000101101100010101010000000100000010000000110000010000001010000000000000000000000010000000000110010000000000011001010000000000010000000000000000000000000000000000010000001000000011000001000000010100000110000001110000100000001001000010100000101100001100000011010000111000001111",2))
	ListItem($packet("11001100110011001100110011001100110011001100110011011101110111011101110111011101110111011101110100001000000000000100010100000000000000000010110000000000000000000000000001100101010000000001000110110100101011000000000100000010000000110000010011000000101010000000000100000010000000000110010000000000011001010000000000010000000000000000000000000000000000010000001000000011000001000000010100000110000001110000100000001001000010100000101100001100000011010000111000001111",4))
</in>

syntax Id ::=
    "bd" [token]
	|"port_mapping" [token]
	|"ipv4_fib_lpm" [token]
	|"ipv4_fib" [token]
	|"nexthop" [token]
	|"rewrite_mac" [token]
