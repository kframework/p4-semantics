     <tables>
        ...
        <table>
            ...
            <name> egress_meter </name>
            <rules> .List => ListItem(
                                $rule(
                                    $ctr(ListItem( @val ( 279611477 , 48 , false )))
                                , @call(String2Id("meter_pkt") , $resolved( ListItem(@val(10,0,false)) ) ))
                             )
            </rules>
        </table>
    </tables>
syntax Id ::=      "egress_meter" [token]
