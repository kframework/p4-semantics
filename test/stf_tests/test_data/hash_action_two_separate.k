
<tables>
    ...

    <table>
        ...
        <t-name> index_setter </t-name>
        <rules> .List => 
        ListItem($rule(0,
                    $ctr(
                        ListItem(@val(286331153,0,false)) ListItem(@val(572662306,0,false))
                    ),
                    @call(
                      String2Id("set_index"),
                      $resolved(
                        ListItem(@val(9,0,false)) ListItem(@val(10,0,false)) ListItem(@val(1,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(1,
                    $ctr(
                        ListItem(@val(572662306,0,false)) ListItem(@val(858993459,0,false))
                    ),
                    @call(
                      String2Id("set_index"),
                      $resolved(
                        ListItem(@val(9,0,false)) ListItem(@val(11,0,false)) ListItem(@val(2,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(2,
                    $ctr(
                        ListItem(@val(858993459,0,false)) ListItem(@val(1145324612,0,false))
                    ),
                    @call(
                      String2Id("set_index"),
                      $resolved(
                        ListItem(@val(9,0,false)) ListItem(@val(11,0,false)) ListItem(@val(2,0,false))
                      )
                    )
                 ))
        

        ListItem($rule(3,
                    $ctr(
                        ListItem(@val(1145324612,0,false)) ListItem(@val(1431655765,0,false))
                    ),
                    @call(
                      String2Id("set_index"),
                      $resolved(
                        ListItem(@val(8,0,false)) ListItem(@val(11,0,false)) ListItem(@val(3,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => .K </default>
    </table>
        
</tables>

<in> .List =>
        ListItem($packet("00010001000100010001000100010001001000100010001000100010001000100000000100000001000000100000001000000011000000110000010000000100",0))
	ListItem($packet("00100010001000100010001000100010001100110011001100110011001100110000001000000010000000110000001100000100000001000000010100000101",0))
	ListItem($packet("00110011001100110011001100110011010001000100010001000100010001000000001100000011000001000000010000000101000001010000011000000110",0))
	ListItem($packet("01000100010001000100010001000100010101010101010101010101010101010000010000000100000001010000010100000110000001100000011100000111",0))
</in>

syntax Id ::=
    "index_setter" [token]
