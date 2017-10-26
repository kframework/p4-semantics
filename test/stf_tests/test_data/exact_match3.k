
<tables>
    ...

    <table>
        ...
        <name> test1 </name>
        <rules> .List => 
        ListItem($rule(0,
                    $ctr(
                        ListItem(@val(16843009,0,false))
                    ),
                    @call(
                      String2Id("setb1"),
                      $resolved(
                        ListItem(@val(127,0,false)) ListItem(@val(2,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(1,
                    $ctr(
                        ListItem(@val(33686018,0,false))
                    ),
                    @call(
                      String2Id("setb1"),
                      $resolved(
                        ListItem(@val(7,0,false)) ListItem(@val(3,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => .K </default>
    </table>
        
</tables>

<in> .List =>
        ListItem($packet("0000000100000001000000010000000100000000000000000000001000000010000000110000001101010101011001100111011110001000",0))
	ListItem($packet("0000001000000010000000100000001000000000000000000000001100000011000001000000010001010101011001100111011110001000",2))
</in>

syntax Id ::=
    "test1" [token]
