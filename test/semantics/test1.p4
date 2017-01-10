header_type ethernet_t {
    fields {
        ethertype: 16;
        dstAddr : 48;
    }
}

header_type foo_t {
    fields {
        bar : 12;
    }
}


header ethernet_t ethernet;
metadata foo_t local_metadata;

parser start {
    return ethernet;
}

parser ethernet {
    extract(ethernet);
    return select(ethernet.ethertype) {
        0x8100:     vlan;
        default:    ingress;
    }
}


parser vlan {

}