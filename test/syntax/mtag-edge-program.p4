header_type ethernet_t {
    fields {
        dst_addr: 48;
        src_addr: 48;
        ethertype: 16;
    }
}

header_type vlan_t {
    fields { pcp: 3;
        cfi:1;
        vid:12;
        ethertype:16;
    }
}

header_type mTag_t {
    fields {
        up1: 8;
        up2: 8;
        down1: 8;
        down2: 8;
        ethertype: 16;
    }
}

header_type ipv4_t {
    fields {
        version:4;
        ihl:4;
        diffserv:8;
        totalLen:16;
        identification  : 16;
        flags:3;
        fragOffset:13;
        ttl:8;
        protocol:8;
        hdrChecksum:16;
        srcAddr:32;
        dstAddr:32;
        options:*;
    }
    length : ihl * 4;
    max_length : 60;
}


header_type local_metadata_t {
    fields {
        cpu_code        : 16; // Code for packet going to CPU
        port_type       : 4;  // Type of port: up, down, local...
        ingress_error   : 1;  // An error in ingress port check
        was_mtagged: 1;  // Track if pkt was mtagged on ingr
        copy_to_cpu : 1;  // Special code resulting in copy to CPU
        bad_packet : 1;  // Other error indication
        color: 8;  // For metering
    }
}


header ethernet_t ethernet;
header vlan_t vlan;
header mTag_t mtag;
header ipv4_t ipv4;
// Local metadata instance declaration
metadata local_metadata_t local_metadata;


////////////////////////////////////////////////////////////////
// Parser state machine description
////////////////////////////////////////////////////////////////
// Start with ethernet always.
parser start {
    return ethernet;
}
parser ethernet {
    extract(ethernet);   // Start with the ethernet header
    return select(latest.ethertype) {
        0x8100:     vlan;
        0x800:      ipv4;
        default:    ingress;
    }
}


// Extract the VLAN tag and check for an mTag
parser vlan {
    extract(vlan);
    return select(latest.ethertype) {
        0xaaaa:     mtag;
        0x800:      ipv4;
        default:    ingress;
    }
}

// mTag is allowed after a VLAN tag only (see above)
parser mtag {
    extract(mtag);
    return select(latest.ethertype) {
    0x800: ipv4;
    default:    ingress;
    }
}
parser ipv4 {
    extract(ipv4);
    return ingress;  // All done with parsing; start matching
}



//actions.p4
//
// This file defines the common actions that can be exercised by
// either an edge or an aggregation switch.
//
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
// Actions used by tables
////////////////////////////////////////////////////////////////
// Copy the packet to the CPU;
action common_copy_pkt_to_cpu(cpu_code, bad_packet) {
    modify_field(local_metadata.copy_to_cpu, 1);
    modify_field(local_metadata.cpu_code, cpu_code);
    modify_field(local_metadata.bad_packet, bad_packet);
}
// Drop the packet; optionally send to CPU and mark bad
action common_drop_pkt(do_copy, cpu_code, bad_packet) {
    modify_field(local_metadata.copy_to_cpu, do_copy);
    modify_field(local_metadata.cpu_code, cpu_code);
    modify_field(local_metadata.bad_packet, bad_packet);
    drop();
}


 // Set the port type; see run time mtag_port_type.
 // Allow error indication.
action common_set_port_type(port_type, ingress_error) {
    modify_field(local_metadata.port_type, port_type);
    modify_field(local_metadata.ingress_error, ingress_error);
}


action _strip_mtag() {
    // Strip the tag from the packet...
    remove_header(mtag);
    // but keep state that it was mtagged.
    modify_field(local_metadata.was_mtagged, 1);
}


table strip_mtag {
    reads {
        mtag : valid;
    }
    actions {
        _strip_mtag;
        no_op;
    }
}


  table identify_port {
        reads {
            standard_metadata.ingress_port : exact;
        }
        actions { // Each table entry specifies *one* action
            common_set_port_type;
            common_drop_pkt;        // If unknown port
            no_op;         // Allow packet to continue
        }
        max_size : 64; // One rule per port
  }


action add_mTag(up1, up2, down1, down2) {
    add_header(mtag);
    // Copy VLAN ethertype to mTag
    modify_field(mtag.ethertype, vlan.ethertype);
    // Set VLAN’s ethertype to signal mTag
    modify_field(vlan.ethertype, 0xaaaa);
    // Add the tag source routing information
    modify_field(mtag.up1, up1);
    modify_field(mtag.up2, up2);
    modify_field(mtag.down1, down1);
    modify_field(mtag.down2, down2);
    //et the destination egress port as well from the tag info
    modify_field(standard_metadata.egress_spec, up1);
}


counter pkts_by_dest {
    type : packets;
    direct : mTag_table;
}
counter bytes_by_dest {
    type : bytes;
    direct : mTag_table;
}

table mTag_table {
    reads {
        ethernet.dst_addr: exact;
        vlan.vid: exact;
    }
    actions {
        add_mTag;  // Action called if pkt needs an mtag.
        // Option: If no mtag setup, forward to the CPU
        common_copy_pkt_to_cpu;
        no_op;
    }
    max_size                 : 20000;
}


table egress_check {
    reads {
        standard_metadata.ingress_port : exact;
        local_metadata.was_mtagged : exact;
    }
    actions {
        common_drop_pkt;
        no_op;
    }
    max_size : 46;
}


meter per_dest_by_source {
    type : bytes;
    result : local_metadata.color;
    instance_count :  4096;  //TODO PORT_COUNT * PORT_COUNT;  // Per source/dest pair
}


action meter_pkt(meter_idx) {
    execute_meter(per_dest_by_source, meter_idx, local_metadata.color);
}


table egress_meter {
    reads {
        standard_metadata.ingress_port : exact;
        mtag.up1 : exact;
    }
    actions {
        meter_pkt;
        no_op;
    }
    size :  4096; //TODO PORT_COUNT * PORT_COUNT;  // Could be smaller
}

counter per_color_drops {
    type : packets;
    direct : meter_policy;
}


table meter_policy {
    reads {

        //metadata.ingress_port : exact; //TODO is it just a typo or it is something else?
        standard_metadata.ingress_port : exact;
        local_metadata.color : exact;
    }
    actions {
        drop;
        no_op;
    }
    size : 256; //TODO 4 * PORT_COUNT;
}



control ingress {
    // Always strip mtag if present, save state
    apply(strip_mtag);
    // Identify the source port type
    apply(identify_port);
    // If no error from source_check, continue
    if (local_metadata.ingress_error == 0) {
        // Attempt to switch to end hosts
        apply(local_switching); // not shown; matches on dest addr
        // If not locally switched, try to setup mtag
        if (standard_metadata.egress_spec == 0) {
            apply(mTag_table);
        }
    }
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