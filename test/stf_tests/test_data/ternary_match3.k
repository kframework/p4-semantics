
<tables>
    ...

    <table>
        ...
        <name> test1 </name>
        <rules> .List => 
        ListItem($rule(0,
                    $ctr(
                        ListItem($pair(@val(269554195,32,false),@val(4294967295,32,false))) ListItem($pair(@val(539042339,32,false),@val(4294967295,32,false))) ListItem($pair(@val(808530483,32,false),@val(4294967295,32,false))) ListItem($pair(@val(1078018627,32,false),@val(4294967295,32,false)))
                    ),
                    @call(
                      String2Id("setb1"),
                      $resolved(
                        ListItem(@val(127,0,false)) ListItem(@val(2,0,false))
                      )
                    )
                 ))
         </rules>
        <default> .K => .K </default>
    </table>
        
</tables>

<in> .List =>
        ListItem($packet("0001000000010001000100100001001100100000001000010010001000100011001100000011000100110010001100110100000001000001010000100100001101010101011001100111011110001000",0))
</in>

syntax Id ::=
    "test1" [token]
