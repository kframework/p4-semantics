
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
                        ListItem(@val(3,0,false)) ListItem(@val(2,0,false))
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
        ListItem($packet("00000001000000010000000100000001000000000000000000000010000000100000000101100110011101111001100100010001001000100011001101000100",0))
	ListItem($packet("00000001000000010000000100000001000000000000000000000010000000100101010101100110100110011001100100010001001000100011001101000100",0))
	ListItem($packet("00000001000000010000000100000001000000010000000100000001000000010101010101100110011101111000100000010001001000100011001101000100",0))
	ListItem($packet("00000000000000000000000100000001000000010000000100000001000000010000000101100110011101111001100100010001001000100011001101000100",0))
</in>

syntax Id ::=
    "test1" [token]
	|"test2" [token]
