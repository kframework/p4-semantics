/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type vlan_tag_t {
    fields {
        pcp : 3;
        cfi : 1;
        vid : 12;
        etherType : 16;
    }
}

header_type mpls_t {
    fields {
        label : 20;
        tc : 3;
        bos : 1;
        ttl : 8;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

parser start {
    return parse_ethernet;
}
header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        0x8100, 0x9100, 0x9200, 0x9300 : parse_vlan;
        0x8847 : parse_mpls;
        0x0800 : parse_ipv4;
        default: ingress;
    }
}


header vlan_tag_t vlan_tag_[2];

parser parse_vlan {
    extract(vlan_tag_[next]);
    return select(latest.etherType) {
        0x8100, 0x9100, 0x9200, 0x9300 : parse_vlan;
        0x8847 : parse_mpls;
        0x0800 : parse_ipv4;
        default: ingress;
    }
}



header mpls_t mpls[3];


header mpls_t mpls_bos;



parser parse_mpls {
    return select(current(23, 1)) {
        0 : parse_mpls_not_bos;
        1 : parse_mpls_bos;
        default: ingress;
    }
}

parser parse_mpls_not_bos {
    extract(mpls[next]);
    return parse_mpls;
}

parser parse_mpls_bos {
    extract(mpls_bos);
    return select(current(0, 4)) {
        0x4 : parse_ipv4;
        default : ingress;
    }
}
header ipv4_t ipv4;

parser parse_ipv4 {
    extract(ipv4);
    return ingress;
}

action do_noop() { }

table do_nothing {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {
        do_noop;
    }
}

control ingress { apply(do_nothing); }
