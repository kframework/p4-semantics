header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        srcAddr : 32;
        dstAddr: 32;
        ttl : 8;
    }
}

header ethernet_t ethernet;
header ipv4_t ipv4;

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        0x0800 : parse_ipv4;
        default: ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    return ingress;
}

action fib_hit_nexthop(nexthop_index) {
    modify_field(standard_metadata.egress_spec, nexthop_index);
    subtract_from_field(ipv4.ttl, 1);
}

table ipv4_fib {
    reads {
        ipv4.dstAddr : exact;
    }
    actions {
        fib_hit_nexthop;
    }
}

control ingress {
    if (valid(ipv4)) {
        apply(ipv4_fib)
    }
}