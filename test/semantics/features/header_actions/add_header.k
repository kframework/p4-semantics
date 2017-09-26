     <tables>
        ...
        <table>
            ...
            <name> t </name>
            <rules> .List   => (
                                 ListItem(
                                    $rule(0,
                                        $ctr(ListItem(@val ( 1 , 0 , false )))
                                    , @call(String2Id("a") , $resolved( .List ) ) )
                                 )
                               )
            </rules>
        </table>
      ...
     </tables>

     //<packet> . => "00000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000001000000000000100010100000000000000000100010010101101000010110000000000000000010000000001000101110010011100100000101000000000000000000000000100001010000000000000000000000000" </packet>
     <buffer>
     <in> .List =>
                   ListItem($packet(
                              ListItem(@val(1,4,false)) //f1
                              ListItem(@val(2,4,false)) //f2
                              , 1 //port
                          ))
     </in>
     ...
     </buffer>

syntax Id ::=       "t" [token]
