     <tables>
        ...
        <table>
            ...
            <name> routing </name>
            <rules> .List   => (
                                 ListItem(
                                     $rule(0,
                                         $ctr(ListItem( false ))
                                     , @call(String2Id("route_ipv4") , $resolved( ListItem (@val (1 , 0 , false) ) ) ) )
                                 )
                                 ListItem(
                                    $rule(1,
                                        $ctr(ListItem( true ))
                                    , @call(String2Id("route_ipv4") , $resolved( ListItem (@val (2 , 0 , false) ) ) ) )
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
     <in> .List => ListItem($packet(

                   ListItem(@val(64,8,false)) //ttl
                   ListItem(@val(167772161,32,false)) //src ip
                   ListItem(@val(167772160,32,false)) //dst ip
                   , 1 //port
                   ))
     </in>
     ...
     </buffer>

syntax Id ::=      "routing" [token]