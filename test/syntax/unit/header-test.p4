header_type hdr_t {
    fields {
        a   : *;
        b   : 4 (signed);
        d   : 10 (saturating);
        e   : 20 (signed,saturating);
    }
    length : 10 + b;
    max_length : 100;
}