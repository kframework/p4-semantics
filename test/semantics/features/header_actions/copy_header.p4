header_type ht {
    fields {
        f1 : 4;
        f2 : 4;
    }
}


header ht h1;
header ht h2;
header ht a[2];

parser start{
    extract(h1);
    return ingress;
}

action a() {
    copy_header(h2,h1);
    copy_header(a[0],h1);
    copy_header(h1,a[1]);
}

table t {
    reads {
        h1.f1 : exact;
    }
    actions {
        a;
    }
}

control ingress{
    apply(t);
}