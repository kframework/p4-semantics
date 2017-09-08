     <tables>
        ...
        <table>
            ...
            <name> routing </name>
            <rules> .List   => (
                                 ListItem(
                                     $rule(
                                         $ctr(ListItem( $pair(@val(167772159,32,false),@val(4294967295, 0, false))))
                                     , @call(String2Id("route_ipv4") , $resolved( ListItem (@val (1 , 0 , false) ) ) ) )
                                 )
                                 ListItem(
                                    $rule(
                                        $ctr(ListItem( $pair(@val(167772160,32,false),@val(3221225472, 0, false))))
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