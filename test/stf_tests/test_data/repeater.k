
<tables>
    ...

    <table>
        ...
        <t-name> repeater </t-name>
        <rules> .List => 
        ListItem($rule(0,
                    $ctr(
                        ListItem(@val(0,0,false))
                    ),
                    @call(
                      String2Id("my_drop"),
                      $resolved(
                        .List
                      )
                    )
                 ))
        

        ListItem($rule(1,
                    $ctr(
                        ListItem(@val(1,0,false))
                    ),
                    @call(
                      String2Id("set_egress_port"),
                      $resolved(
                        ListItem(@val(2,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(2,
                    $ctr(
                        ListItem(@val(2,0,false))
                    ),
                    @call(
                      String2Id("my_drop"),
                      $resolved(
                        .List
                      )
                    )
                 ))
        

        ListItem($rule(3,
                    $ctr(
                        ListItem(@val(3,0,false))
                    ),
                    @call(
                      String2Id("set_egress_port"),
                      $resolved(
                        ListItem(@val(1,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => .K </default>
    </table>
        
</tables>

<in> .List =>
        ListItem($packet("0000000100000001000000010000000100000001000000010000000100000001",0))
	ListItem($packet("0000001000000010000000100000001000000010000000100000001000000010",1))
	ListItem($packet("0000001100000011000000110000001100000011000000110000001100000011",2))
	ListItem($packet("0000010000000100000001000000010000000100000001000000010000000100",3))
</in>

syntax Id ::=
    "repeater" [token]
