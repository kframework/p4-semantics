header_type ht {
    fields {
        f1 : 4;
        f2 : 4;
    }
}



header ht a[6];

parser start{
    extract(a[0]);
    extract(a[3]);
    return ingress;
}

action a() {
    pop(a,2);
}

table t {
    reads {
        a[0].f1 : exact;
    }
    actions {
        a;
    }
}

control ingress{
    apply(t);
}