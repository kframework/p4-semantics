
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
                        ListItem(@val(3,0,false)) ListItem(@val(7,0,false))
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
                        ListItem(@val(2,0,false)) ListItem(@val(127,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => .K </default>
    </table>
        
    <table>
        ...
        <name> tbl1 </name>
        <rules> .List => 
        ListItem($rule(3,
                    $ctr(
                        ListItem($pair(@val(33685504,32,false),@val(4294901760,32,false)))
                    ),
                    @call(
                      String2Id("setb2"),
                      $resolved(
                        ListItem(@val(38,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => .K </default>
    </table>
        
    <table>
        ...
        <name> tbl2 </name>
        <rules> .List => 
        ListItem($rule(5,
                    $ctr(
                        ListItem($pair(@val(33685504,32,false),@val(4294901760,32,false)))
                    ),
                    @call(
                      String2Id("set1b1"),
                      $resolved(
                        ListItem(@val(40,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => .K </default>
    </table>
        
    <table>
        ...
        <name> ex1 </name>
        <rules> .List => 
        ListItem($rule(4,
                    $ctr(
                        ListItem($pair(@val(9509,16,false),@val(65535,16,false)))
                    ),
                    @call(
                      String2Id("act2"),
                      $resolved(
                        ListItem(@val(39,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(2,
                    $ctr(
                        ListItem($pair(@val(9472,16,false),@val(65280,16,false)))
                    ),
                    @call(
                      String2Id("act1"),
                      $resolved(
                        ListItem(@val(37,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => .K </default>
    </table>
        
</tables>

<in> .List =>
        ListItem($packet("00000000000000000000000100000001000000000000000000000010000000100000001100000011010101010110011001110111011101111000100000000000",0))
	ListItem($packet("00000000000000000000001000000010000000000000000000000011000000110000010000000100010101010110011001110111011101111000100000000000",2))
	ListItem($packet("0000000100000001000000010000000100000010000000100000001000000010000000110000001101010101011001100010010100000000111111110111111100000001000000100000001100000100",0))
	ListItem($packet("000000010000000100000001000000010000001000000010000000100000001000000011000000110101010101100110001001010010010111111111111111110011001100110011111111110111111100000001000000100000001100000100",0))
</in>

syntax Id ::=
    "test1" [token]
	|"tbl1" [token]
	|"tbl2" [token]
	|"ex1" [token]
