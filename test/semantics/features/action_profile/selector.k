     <tables>
        ...
        <table>
            ...
            <name> test1 </name>
            <rules> .List   => (
                                 ListItem(
                                    $rule(0,
                                        $ctr(ListItem(@val ( 0 , 0 , false )))
                                    ,   @apref(0) )
                                 )
                               )
            </rules>
        </table>
      ...
     </tables>
     <actionProfiles>
        ...
        <actionProfile>
            <name> sel_profile </name>
            <entries> (.Map => 0 |-> (
                                        ListItem(@call(String2Id("setf1") , $resolved(ListItem(@val(10,0,false)))))
                                        ListItem(@call(String2Id("setf1") , $resolved(ListItem(@val(20,0,false)))))
                                     )
                      )
            </entries>
            ...
        </actionProfile>
     </actionProfiles>
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
                              ListItem(@val(1,32,false))
                              ListItem(@val(0,8,false))
                              , 1 //port
                          ))
     </in>
     ...
     </buffer>

syntax Id ::=      "test1" [token]
                |   "sel_profile" [token]