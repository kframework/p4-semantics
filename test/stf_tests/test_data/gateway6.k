
<tables>
    ...

    <table>
        ...
        <t-name> test1 </t-name>
        <rules> .List => 
        ListItem($rule(0,
                    $ctr(
                        ListItem(@val(305419896,0,false))
                    ),
                    @call(
                      String2Id("output"),
                      $resolved(
                        ListItem(@val(2,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => .K </default>
    </table>
        
    <table>
        ...
        <t-name> test2 </t-name>
        <rules> .List => 
        ListItem($rule(1,
                    $ctr(
                        ListItem(@val(305419896,0,false))
                    ),
                    @call(
                      String2Id("output"),
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
        ListItem($packet("00010010001101000101011001111000000100100011010001010110011110000000000000000001000000000000000011110001",0))
	ListItem($packet("00010010001101000101011001111000000100100011010001010110011110000000000000000010000000000000000011110010",0))
	ListItem($packet("00010010001101000101011001111000000100100011010001010110011110000000000011110001000000000000000011110011",0))
</in>

syntax Id ::=
    "test1" [token]
	|"test2" [token]
