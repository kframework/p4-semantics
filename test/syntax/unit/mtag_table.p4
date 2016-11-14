// Check if the packet needs an mtag and add one if it does.
table mTag_table {
    reads {
        ethernet.dst_addr   : exact;
        vlan.vid            : exact;
    }
    actions {
        add_mTag;     // Action called if pkt needs an mtag.
        common_copy_pkt_to_cpu; // If no mtag, send to the CPU
        no_op;
    }
    max_size                 : 20000;
}