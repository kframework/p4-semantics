header_type ethernet_t {
    fields {
        ethertype: 16;
        dstAddr : 48;
    }
}

header_type y_t {
    fields {
        xx : 12;
    }
}


header ethernet_t ethernet;
metadata y_t local_metadata;
header ethernet_t ethernet2;
header ethernet_t ethernet3;

parser start {
    return ethernet;
}

parser ethernet {
    extract(ethernet);
    return select(ethernet.ethertype) {
        0x8100:     vlan;
        default:    xxx;
    }
}

parser vlan {
    extract(ethernet2);
    return xxx;
}

parser xxx {
    extract(ethernet3);
    return ingress;
}

action meter_pkt(meter_idx) {
    execute_meter(meter_idx, per_dest_by_source, meter_idx, local_metadata.color);
}

table egress_meter {
    reads {
        //standard_metadata.ingress_port : exact;
        ethernet.dstAddr : exact;
    }
    actions {
        meter_pkt;
        no_op;
    }
    //size :  4096; //TODO PORT_COUNT * PORT_COUNT;  // Could be smaller
}


control ingress {
    if (ethernet.dstAddr == 10 or true) {
        apply(egress_meter) {
                hit {
                    ctrl();
                }
        }
    }
    // Always strip mtag if present, save state
    //apply(strip_mtag);
    // Identify the source port type
    //apply(identify_port);
    // If no error from source_check, continue
    //if (local_metadata.ingress_error == 0) {
        // Attempt to switch to end hosts
     //   apply(local_switching); // not shown; matches on dest addr
        // If not locally switched, try to setup mtag
    //    if (standard_metadata.egress_spec == 0) {
     //       apply(mTag_table);
     //   }
   // }
}

control ctrl {

}

control egress {
    // Check for unknown egress state or bad retagging with mTag.
    apply(egress_check);
    // Apply egress_meter table; if hit, apply meter policy
    apply(egress_meter) {
        hit {
            apply(meter_policy);
        }
    }
}