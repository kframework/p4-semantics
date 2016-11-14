parser vlan {
    extract(vlan);
    return select(latest.ethertype) {
        0xaaaa:     mtag;
        0x800: ipv4;
                default:    ingress;
    }
}

