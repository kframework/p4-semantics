
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
                        ListItem(@val(1,0,false)) ListItem(@val(2,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => .K </default>
    </table>
        
    <table>
        ...
        <name> test2 </name>
        <rules> .List => 
        ListItem($rule(1,
                    $ctr(
                        ListItem(@val(16843009,0,false))
                    ),
                    @call(
                      String2Id("setb1"),
                      $resolved(
                        ListItem(@val(2,0,false)) ListItem(@val(3,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => .K </default>
    </table>
        
</tables>

<in> .List =>
        ListItem($packet("000000010000000100000001000000010000000000000000000000100000001001010101000000010111011110001000",0))
	ListItem($packet("000000010000000100000001000000010000000000000000000000100000001001010101011001101001100110101010",0))
	ListItem($packet("000000010000000100000001000000010000000100000001000000010000000101010101011001100111011110001000",0))
</in>

syntax Id ::=
    "test1" [token]
	|"test2" [token]
