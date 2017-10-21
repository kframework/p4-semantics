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

action a(v) {
    modify_field(h.f2, v);
}

table t {
    reads {
        h.f1 : exact;
    }
    actions {
        a;
    }
}

control ingress{
    apply(t);
}