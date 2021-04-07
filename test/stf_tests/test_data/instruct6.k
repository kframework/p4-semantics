
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
                      String2Id("op1"),
                      $resolved(
                        ListItem(@val(2,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(1,
                    $ctr(
                        ListItem(@val(33686018,0,false))
                    ),
                    @call(
                      String2Id("op2"),
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
        ListItem($packet("000000010000000100000001000000010000001000000010000000100000001000010001001000100011001101000100010101010110011001110111100010001001100110101010",0))
	ListItem($packet("000000100000001000000010000000100000000100000001000000010000000100010001001000100011001101000100010101010110011001110111100010001001100110101010",0))
</in>

syntax Id ::=
    "test1" [token]
