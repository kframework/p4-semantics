
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
                        ListItem(@val(9,0,false)) ListItem(@val(1,0,false))
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
                        ListItem(@val(9,0,false)) ListItem(@val(2,0,false))
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
                        ListItem(@val(9,0,false)) ListItem(@val(2,0,false))
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
                        ListItem(@val(8,0,false)) ListItem(@val(3,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => .K </default>
    </table>
        
</tables>

<in> .List =>
        ListItem($packet("00010001000100010001000100010001001000100010001000100010001000100000000100000001000000100000001000000011000000110000010000000100",0))
</in>

syntax Id ::=
    "index_setter" [token]
