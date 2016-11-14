parser mtag {
    extract(mtag);
    return select(latest.ethertype) {
        0x800:      ipv4;
        default:    ingress;
    }
}