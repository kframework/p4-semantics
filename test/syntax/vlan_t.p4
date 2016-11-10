header_type vlan_t {
    fields {
        pcp             : 3;
        cfi             : 1;
        vid             : 12;
        ethertype       : 16;
    }
}