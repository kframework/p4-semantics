
                    //00:00:00:00:00:01 00:00:00:00:00:00   ....  TTL:64 .... 10.0.0.1 10.0.0.0
                    //0000 0000 0001 0000 0000 0000 0800 4500 0044 ad0b 0000 4011 7272 0a00 0001 0a00 0000
     //<packet> . => "00000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000001000000000000100010100000000000000000100010010101101000010110000000000000000010000000001000101110010011100100000101000000000000000000000000100001010000000000000000000000000" </packet>
     <buffer>
     <in> .List => ListItem($packet(
                   ListItem(@val(1,48,false)) //dst mac
                   ListItem(@val(0,48,false)) //src mac
                   ListItem(@val(2048,16,false)) //ethertype
                   ListItem(@val(4,4,false)) //ip version
                   ListItem(@val(20,4,false)) //ihl
                   ListItem(@val(0,8,false)) //diffserv
                   ListItem(@val(68,16,false)) //total len
                   ListItem(@val(44299,16,false)) //id
                   ListItem(@val(0,3,false)) //flags
                   ListItem(@val(0,13,false)) //frag offset
                   ListItem(@val(64,8,false)) //ttl
                   ListItem(@val(17,8,false)) //protocol
                   ListItem(@val(7272,16,false)) //checksum
                   ListItem(@val(167772161,32,false)) //src ip
                   ListItem(@val(167772160,32,false)) //dst ip
                   , 1 //port
                   ))
     </in>
     ...
     </buffer>
