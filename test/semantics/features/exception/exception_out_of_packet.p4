header_type ht {
    fields {
        f1 : 4;
        f2 : 4;
    }
}

header_type mdt {
    fields {
        f : 8;
    }
}


header ht h;
metadata mdt md;

parser start{
    extract(h);
    return ingress;
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