     <tables>
        ...
        <table>
            ...
            <name> read_reg_table </name>
            <rules> .List   => (
                                 ListItem(
                                    $rule(0,
                                        $ctr(ListItem(@val ( 1 , 0 , false )))
                                    , @call(String2Id("read_reg") , $resolved( .List ) ) )
                                 )
                               )
            </rules>
        </table>
        <table>
            ...
            <name> balance_table </name>
            <rules> .List   => (
                                 ListItem(
                                    $rule(0,
                                        $ctr(ListItem(@val ( 0 , 0 , false )))
                                    , @call(String2Id("balance") , $resolved( ListItem(@val(0,0,false)) ListItem(@val(1,0,false)) ) ) )
                                 )
                                 ListItem(
                                     $rule(1,
                                         $ctr(ListItem(@val ( 1 , 0 , false )))
                                     , @call(String2Id("balance") , $resolved( ListItem(@val(1,0,false)) ListItem(@val(0,0,false)) ) ) )
                                  )
                               )
            </rules>
        </table>

     </tables>

     <buffer>
     <in> .List => (
                   ListItem($packet(ListItem(@val(1,8,false)),10))
                   ListItem($packet(ListItem(@val(2,8,false)),10))
                   ListItem($packet(ListItem(@val(3,8,false)),10))
                   )
     </in>
     ...
     </buffer>

syntax Id ::=      "read_reg_table" [token] | "balance_table" [token]