header_type h_t {
    fields {
        f1 : 8;
        f2 : 8;
    }
}

header h_t h1;


parser start {
    extract(h1);
    return ingress;
}


action a(n) {
    modify_field(h1.f2, n);
    modify_field(standard_metadata.egress_spec, 1);
}

action b() {
    modify_field(standard_metadata.egress_spec, 2);
}

table t {
    reads {
        h1.f1 : exact;
    }
    actions {
        a;
        b;
    }
}

control ingress {
    apply(t);
}

