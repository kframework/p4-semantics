header_type h_t {
    fields {
        f1 : 8;
        f2 : 8;
    }
}

header h_t h1;
header h_t h2;

parser start {
    extract(h1);
    return select(h1.f1){
        1       : parse_h2;
        default : ingress;
    }
}

parser parse_h2 {
    extract(h2);
    return ingress;
}

action a(n) {
    modify_field(h2.f2, n);
    modify_field(standard_metadata.egress_spec, 10);
}

action b() {
    modify_field(standard_metadata.egress_spec, 20);
}

table t {
    reads {
        h2.f1 : exact;
        h2.f2 : exact;
    }
    actions {
        a;
        b;
    }
}

control ingress {
    if (valid(h2)) {
        apply(t);
    }
}

