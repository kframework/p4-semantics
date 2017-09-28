header_type ht {
    fields {
        f : 8;
    }
}

header ht h;

parser start{
    extract(h);
    return ingress;
}

control ingress {

    if ((h.f != 0) and (h.f != 1)){

    }
}
