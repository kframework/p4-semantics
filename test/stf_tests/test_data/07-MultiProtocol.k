
<tables>
    ...

    <table>
        ...
        <t-name> set_egress </t-name>
        <rules> .List => 
        ListItem($rule(4,
                    $ctr(
                        ListItem(@val(0,0,false))
                    ),
                    @call(
                      String2Id("send_packet"),
                      $resolved(
                        .List
                      )
                    )
                 ))
        

        ListItem($rule(5,
                    $ctr(
                        ListItem(@val(1,0,false))
                    ),
                    @call(
                      String2Id("nop"),
                      $resolved(
                        .List
                      )
                    )
                 ))
         </rules>
        <default> .K => .K </default>
    </table>
        
    <table>
        ...
        <t-name> udp_check </t-name>
        <rules> .List => 
        ListItem($rule(7,
                    $ctr(
                        ListItem(@val(170,0,false))
                    ),
                    @call(
                      String2Id("_drop"),
                      $resolved(
                        .List
                      )
                    )
                 ))
         </rules>
        <default> .K => .K </default>
    </table>
        
    <table>
        ...
        <t-name> ethertype_match </t-name>
        <rules> .List => 
        ListItem($rule(0,
                    $ctr(
                        ListItem(@val(2048,0,false))
                    ),
                    @call(
                      String2Id("ipv4_packet"),
                      $resolved(
                        .List
                      )
                    )
                 ))
        

        ListItem($rule(1,
                    $ctr(
                        ListItem(@val(34525,0,false))
                    ),
                    @call(
                      String2Id("ipv6_packet"),
                      $resolved(
                        .List
                      )
                    )
                 ))
        

        ListItem($rule(2,
                    $ctr(
                        ListItem(@val(33024,0,false))
                    ),
                    @call(
                      String2Id("mpls_packet"),
                      $resolved(
                        .List
                      )
                    )
                 ))
        

        ListItem($rule(3,
                    $ctr(
                        ListItem(@val(37120,0,false))
                    ),
                    @call(
                      String2Id("mim_packet"),
                      $resolved(
                        .List
                      )
                    )
                 ))
         </rules>
        <default> .K => 
            @call(
              String2Id("l2_packet"),
              $resolved(
                .List
              )
            )
         </default>
    </table>
        
    <table>
        ...
        <t-name> ipv4_match </t-name>
        <rules> .List => 
        ListItem($rule(6,
                    $ctr(
                        ListItem(@val(167772162,0,false))
                    ),
                    @call(
                      String2Id("set_egress_port"),
                      $resolved(
                        ListItem(@val(3,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => .K </default>
    </table>
        
</tables>

<in> .List =>
        ListItem($packet("10101010101010101010101010101010101010101010101010111011101110111011101110111011101110111011101100001000000000000100010100000000000000000010110000000000000000000000000001100101010000000001000101101100010101010000000100000010000000110000010000001010000000000000000000000010000000000110010000000000101010100000000000010000000000000000000000000000000000010000001000000011000001000000010100000110000001110000100000001001000010100000101100001100000011010000111000001111",0))
	ListItem($packet("10101010101010101010101010101010101010101010101010111011101110111011101110111011101110111011101100001000000000000100010100000000000000000010110000000000000000000000000001100101010000000001000101101100010101010000000100000010000000110000010000001010000000000000000000000010000000000110010000000000011001010000000000010000000000000000000000000000000000010000001000000011000001000000010100000110000001110000100000001001000010100000101100001100000011010000111000001111",0))
</in>

syntax Id ::=
    "set_egress" [token]
	|"udp_check" [token]
	|"ethertype_match" [token]
	|"ipv4_match" [token]
