
<tables>
    ...

    <table>
        ...
        <name> test1 </name>
        <rules> .List => 
        ListItem($rule(1,
                    $ctr(
                        ListItem($pair(@val(514,32,false),@val(65535,32,false)))
                    ),
                    @call(
                      String2Id("setb1"),
                      $resolved(
                        ListItem(@val(3,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(0,
                    $ctr(
                        ListItem($pair(@val(257,32,false),@val(65535,32,false)))
                    ),
                    @call(
                      String2Id("setb1"),
                      $resolved(
                        ListItem(@val(2,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => .K </default>
    </table>
        
</tables>

<in> .List =>
        ListItem($packet("0000000000000000000000010000000100000000000000000000001000000010000000000000000000000011000000110000000000000000000001000000010001010101011001100111011110001000",0))
	ListItem($packet("0000000000000000000000100000001000000000000000000000001100000011000000000000000000000100000001000000000000000000000001000000010001010101011001100111011110001000",2))
</in>

syntax Id ::=
    "test1" [token]
