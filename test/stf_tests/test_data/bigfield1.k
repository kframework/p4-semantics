
<tables>
    ...

    <table>
        ...
        <t-name> test1 </t-name>
        <rules> .List => 
        ListItem($rule(0,
                    $ctr(
                        ListItem(@val(16843009,0,false))
                    ),
                    @call(
                      String2Id("setx1"),
                      $resolved(
                        ListItem(@val(89340438974721,0,false)) ListItem(@val(2,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(1,
                    $ctr(
                        ListItem(@val(33686018,0,false))
                    ),
                    @call(
                      String2Id("setx1"),
                      $resolved(
                        ListItem(@val(0,0,false)) ListItem(@val(3,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => .K </default>
    </table>
        
</tables>

<in> .List =>
        ListItem($packet("000000010000000100000001000000010000000000000000000000100000001000000011000000110000001100000011000000110000001101010101011001100111011110001000",0))
	ListItem($packet("000000100000001000000010000000100000000000000000000000110000001100000100000001000000010000000100000001000000010001010101011001100111011110001000",2))
</in>

syntax Id ::=
    "test1" [token]
