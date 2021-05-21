




header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header ethernet_t ethernet;

header_type arp_t {
    fields {
        hrd : 16;
        pro : 16;
        hln : 8;
        pln : 8;
        op : 16;
        sha : 48;
        spa : 32;
        tha : 48;
        tpa : 32;
    }
}
header arp_t arp;

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header ipv4_t ipv4;
/*
field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum {
    verify ipv4_checksum;
    update ipv4_checksum;
}
*/
header_type ipv6_t {
    fields {
        version : 4;
        trafficClass : 8;
        flowLabel : 20;
        payloadLen : 16;
        nextHdr : 8;
        hopLimit : 8;
        srcAddr : 128;
        dstAddr : 128;
    }
}

header ipv6_t ipv6;

header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        length_ : 16;
        checksum : 16;
    }
}

header udp_t udp;

field_list udp_checksum_list {
    ipv4.srcAddr;
    ipv4.dstAddr;
    8'0;
    ipv4.protocol;
    udp.length_;
    udp.srcPort;
    udp.dstPort;
    udp.length_;
    payload;
}

header_type igmp_t {
    fields {
        msgtype : 8;
        max_resp : 8;
        checksum : 16;
        grp_addr : 32;
    }
}

header igmp_t igmp;
parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        0x0806 : parse_arp;
        0x0800 : parse_ipv4;
        0x86dd : parse_ipv6;
        default : ingress;
    }
}

parser parse_arp {
    extract(arp);
    return ingress;
}

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
        0x11 : parse_udp;
        default : ingress;
    }
}

parser parse_ipv6 {
    extract(ipv6);
    return ingress;
}

parser parse_udp {
    extract(udp);
    return select(udp.dstPort) {
        0x8888 : parse_paxos;
        0x8889 : parse_paxos;
        default: ingress;
    }
}
header_type paxos_t {
    fields {
        msgtype : 16;
        inst : 32;
        rnd : 16;
        vrnd : 16;
        acptid : 16;
        paxoslen : 32;
        paxosval : 256;
    }
}

header paxos_t paxos;





parser parse_paxos {
    extract(paxos);
    return ingress;
}


header_type ingress_metadata_t {
    fields {
        round : 16;
        set_drop : 1;
    }
}

metadata ingress_metadata_t local_metadata;

register datapath_id {
    width: 16;
    static : acceptor_tbl;
    instance_count : 1;
}

register rounds_register {
    width : 16;
    instance_count : 65536;
}

register vrounds_register {
    width : 16;
    instance_count : 65536;
}

register values_register {
    width : 256;
    instance_count : 65536;
}

action _nop() {

}

action _drop() {
    drop();
}




action read_round() {
    register_read(local_metadata.round, rounds_register, 0);
    modify_field(local_metadata.set_drop, 1);
}

table round_tbl {
    actions { read_round; }
    size : 1;
}


action handle_1a(learner_port) {
    modify_field(paxos.msgtype, 1);
    register_read(paxos.vrnd, vrounds_register, 0);
    register_read(paxos.paxosval, values_register, 0);
    register_read(paxos.acptid, datapath_id, 0);
    register_write(rounds_register, 0, paxos.rnd);
    modify_field(udp.dstPort, learner_port);
    modify_field(udp.checksum, 0);
}


action handle_2a(learner_port) {
    modify_field(paxos.msgtype, 3);
    register_write(rounds_register, 0, paxos.rnd);
    register_write(vrounds_register, 0, paxos.rnd);
    register_write(values_register, 0, paxos.paxosval);
    register_read(paxos.acptid, datapath_id, 0);
    modify_field(udp.dstPort, learner_port);
    modify_field(udp.checksum, 0);
}

table acceptor_tbl {
    reads { paxos.msgtype : exact; }
    actions { handle_1a; handle_2a; _drop; }
}

action forward(port) {
    modify_field(standard_metadata.egress_spec, port);
}

table forward_tbl {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
        forward;
        _drop;
    }
    size : 48;
}

table drop_tbl {
    reads {
        local_metadata.set_drop : exact;
    }
    actions { _drop; _nop; }
    size : 2;
}

control ingress {
    if (valid(ipv4)) {
        apply(forward_tbl);
    }

    if (valid(paxos)) {
        apply(round_tbl);
        if (local_metadata.round <= paxos.rnd) {
            @assert [nodrop] (not #isReached) or #isForwarded;
            apply(acceptor_tbl);
        }
    }
}

control egress {
    apply(drop_tbl);
}
