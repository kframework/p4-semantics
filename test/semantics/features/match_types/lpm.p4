header_type ipv4_t {
    fields {
        ttl             : 8;
        srcAddr         : 32;
        dstAddr         : 32;

    }
}

header ipv4_t ipv4;

parser start{
    extract(ipv4);
    return ingress;
}



action route_ipv4(egress_spec) {
    add_to_field(ipv4.ttl, -1);
    modify_field(standard_metadata.egress_spec, egress_spec);
}

table routing {
    reads {
	    ipv4.dstAddr : lpm;
    }
    actions {
        route_ipv4;
    }
}


control ingress {
    apply(routing);
}

control egress {
}
