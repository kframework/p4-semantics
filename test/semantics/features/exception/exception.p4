header_type ht {
    fields {
        f1 : 4;
        f2 : 4;
    }
}

header ht h;

parser start{
    extract(h);
    return ingress;
}

parser_exception p4_pe_out_of_packet {
    parser_drop;
}

action noop() {

}

table t {
    reads {
        h.f1 : exact;
    }
    actions {
        noop;
    }
}

control ingress{
    apply(t);
}