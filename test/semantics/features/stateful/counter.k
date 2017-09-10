     <tables>
        ...
        <table>
            ...
            <name> m_table </name>
            <rules> .List   => (
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem(@val ( 0 , 0 , false )))
                                    , @call(String2Id("m_action") , $resolved( ListItem(@val(0,0,false)) ) ) )
                                 )
                               )
            </rules>
        </table>
      ...
     </tables>
                    //00:00:00:00:00:01 00:00:00:00:00:00   ....  TTL:64 .... 10.0.0.1 10.0.0.0
                    //0000 0000 0001 0000 0000 0000 0800 4500 0044 ad0b 0000 4011 7272 0a00 0001 0a00 0000
     //<packet> . => "00000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000001000000000000100010100000000000000000100010010101101000010110000000000000000010000000001000101110010011100100000101000000000000000000000000100001010000000000000000000000000" </packet>
     <buffer>
     <in> .List => /*ListItem($packet(
                               ListItem(@val(11,48,false)) //dst mac
                               ListItem(@val(10,48,false)) //src mac
                               ListItem(@val(2048,16,false)) //ethertype
                               , 1 //port
                           ))*/
                   ListItem($packet(
                              ListItem(@val(1,48,false)) //dst mac
                              ListItem(@val(0,48,false)) //src mac
                              ListItem(@val(2048,16,false)) //ethertype
                              , 1 //port
                          ))
     </in>
     ...
     </buffer>

syntax Id ::=      "m_table" [token]