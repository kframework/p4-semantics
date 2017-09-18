
header_type ht {
    fields {
        f1 : 2;
        f2 : 2;
    }
}

header ht h[2];

parser start{
    extract(h[next]);
    return select(latest.f1){
        0 : start;
        1 : ingress;
    }
}

action ac (val) {
    modify_field(h[0].f2 , val);
    modify_field(h[last].f2 , val);
}

table t {
    reads {
        h[0].f1 : exact;
        h[last].f1 : exact;
    }
    actions {
        ac;
    }
}

control ingress { apply(t); }
