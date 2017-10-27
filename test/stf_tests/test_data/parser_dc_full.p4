header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type snap_header_t {
    fields {
        dsap : 8;
        ssap : 8;
        control_ : 8;
        oui : 24;
        type_ : 16;
    }
}

header_type roce_header_t {
    fields {
        ib_grh : 320;
        ib_bth : 96;
    }
}

header_type roce_v2_header_t {
    fields {
        ib_bth : 96;
    }
}

header_type fcoe_header_t {
    fields {
        version : 4;
        type_ : 4;
        sof : 8;
        rsvd1 : 32;
        ts_upper : 32;
        ts_lower : 32;
        size_ : 32;
        eof : 8;
        rsvd2 : 24;
    }
}

header_type cpu_header_t {
    fields {
        qid : 3;
        pad : 1;
        reason_code : 12;
        rxhash : 16;
        bridge_domain : 16;
        ingress_lif : 16;
        egress_lif : 16;
        lu_bypass_ingress : 1;
        lu_bypass_egress : 1;
        pad1 : 14;
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

header_type vlan_tag_3b_t {
    fields {
        pcp : 3;
        cfi : 1;
        vid : 4;
        etherType : 16;
    }
}
header_type vlan_tag_5b_t {
    fields {
        pcp : 3;
        cfi : 1;
        vid : 20;
        etherType : 16;
    }
}

header_type ieee802_1ah_t {
    fields {
        pcp : 3;
        dei : 1;
        uca : 1;
        reserved : 3;
        i_sid : 24;
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

header_type ipv6_t {
    fields {
        version : 4;
        trafficClass : 8;
        flowLabel : 20;
        payloadLen : 16;
        nextHdr : 8;
        hopLimit : 8;
        srcAddr : 128;
        dstAddr : 128;
    }
}

header_type icmp_t {
    fields {
        type_ : 8;
        code : 8;
        hdrChecksum : 16;
    }
}

header_type icmpv6_t {
    fields {
        type_ : 8;
        code : 8;
        hdrChecksum : 16;
    }
}

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 4;
        flags : 8;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        length_ : 16;
        checksum : 16;
    }
}

header_type sctp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        verifTag : 32;
        checksum : 32;
    }
}

header_type gre_t {
    fields {
        C : 1;
        R : 1;
        K : 1;
        S : 1;
        s : 1;
        recurse : 3;
        flags : 5;
        ver : 3;
        proto : 16;
    }
}

header_type nvgre_t {
    fields {
        tni : 24;
        reserved : 8;
    }
}


header_type erspan_header_v1_t {
    fields {
        version : 4;
        vlan : 12;
        priority : 6;
        span_id : 10;
        direction : 8;
        truncated: 8;
    }
}


header_type erspan_header_v2_t {
    fields {
        version : 4;
        vlan : 12;
        priority : 6;
        span_id : 10;
        unknown7 : 32;
    }
}

header_type ipsec_esp_t {
    fields {
        spi : 32;
        seqNo : 32;
    }
}

header_type ipsec_ah_t {
    fields {
        nextHdr : 8;
        length_ : 8;
        zero : 16;
        spi : 32;
        seqNo : 32;
    }
}

header_type arp_rarp_t {
    fields {
        hwType : 16;
        protoType : 16;
        hwAddrLen : 8;
        protoAddrLen : 8;
        opcode : 16;
    }
}

header_type arp_rarp_ipv4_t {
    fields {
        srcHwAddr : 48;
        srcProtoAddr : 32;
        dstHwAddr : 48;
        dstProtoAddr : 32;
    }
}

header_type eompls_t {
    fields {
        zero : 4;
        reserved : 12;
        seqNo : 16;
    }
}

header_type vxlan_t {
    fields {
        flags : 8;
        reserved : 24;
        vni : 24;
        reserved2 : 8;
    }
}

header_type nsh_t {
    fields {
        oam : 1;
        context : 1;
        flags : 6;
        reserved : 8;
        protoType: 16;
        spath : 24;
        sindex : 8;
    }
}

header_type nsh_context_t {
    fields {
        network_platform : 32;
        network_shared : 32;
        service_platform : 32;
        service_shared : 32;
    }
}




header_type genv_t {
    fields {
        ver : 2;
        optLen : 6;
        oam : 1;
        critical : 1;
        reserved : 6;
        protoType : 16;
        vni : 24;
        reserved2 : 8;
    }
}





header_type genv_opt_A_t {
    fields {
        optClass : 16;
        optType : 8;
        reserved : 3;
        optLen : 5;
        data : 32;
    }
}




header_type genv_opt_B_t {
    fields {
        optClass : 16;
        optType : 8;
        reserved : 3;
        optLen : 5;
        data : 64;
    }
}




header_type genv_opt_C_t {
    fields {
        optClass : 16;
        optType : 8;
        reserved : 3;
        optLen : 5;
        data : 32;
    }
}
parser start {
    return parse_input_port;
}

header_type input_port_hdr_t {
    fields {
        port : 16;
    }
}

header input_port_hdr_t input_port_hdr;

parser parse_input_port {
    extract (input_port_hdr);
    return parse_ethernet;
}
header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        0 mask 0xf800: parse_snap_header;
        0x9000, 0x010c : parse_cpu_header;
        0x8100, 0x9100, 0x9200, 0x9300 : parse_vlan;
        0x8847 : parse_mpls;
        0x0800 : parse_ipv4;
        0x86dd : parse_ipv6;
        0x0806 : parse_arp_rarp;
        0x8035 : parse_arp_rarp;
        0x894f : parse_nsh;
        0x8915: parse_roce;
        0x8906: parse_fcoe;
        default: parse_payload;
    }
}

header snap_header_t snap_header;

parser parse_snap_header {
    extract(snap_header);
    return parse_payload;
}

header roce_header_t roce;

parser parse_roce {
    extract(roce);
    return parse_payload;
}

header fcoe_header_t fcoe;

parser parse_fcoe {
    extract(fcoe);
    return parse_payload;
}

header cpu_header_t cpu_header;

parser parse_cpu_header {
    extract(cpu_header);
    return select(latest.etherType) {
        0 mask 0xf800: parse_snap_header;
        0x8100, 0x9100, 0x9200, 0x9300 : parse_vlan;
        0x8847 : parse_mpls;
        0x0800 : parse_ipv4;
        0x86dd : parse_ipv6;
        0x0806 : parse_arp_rarp;
        0x8035 : parse_arp_rarp;
        0x894f : parse_nsh;
        0x8915: parse_roce;
        0x8906: parse_fcoe;
        default: parse_payload;
    }
}


header vlan_tag_t vlan_tag_[2];
header vlan_tag_3b_t vlan_tag_3b[2];
header vlan_tag_5b_t vlan_tag_5b[2];

parser parse_vlan {
    extract(vlan_tag_[next]);
    return select(latest.etherType) {
        0x8100, 0x9100, 0x9200, 0x9300 : parse_vlan;
        0x8847 : parse_mpls;
        0x0800 : parse_ipv4;
        0x86dd : parse_ipv6;
        0x0806 : parse_arp_rarp;
        0x8035 : parse_arp_rarp;
        default: parse_payload;
    }
}



header mpls_t mpls[3];


header mpls_t mpls_bos;



parser parse_mpls {
    return select(current(23, 1)) {
        //0 : parse_mpls_not_bos;
        //1 : parse_mpls_bos; Ali, temporary workaround for deparse order inference problem
        1 : parse_mpls_bos;
        0 : parse_mpls_not_bos;
        default: parse_payload;
    }
}

parser parse_mpls_not_bos {
    extract(mpls[next]);
    return parse_mpls;
}

parser parse_mpls_bos {
    extract(mpls_bos);
    return select(current(0, 4)) {
        0x4 : parse_inner_ipv4;
        0x6 : parse_inner_ipv6;
        default : parse_eompls;
    }
}
header ipv4_t ipv4;

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum {
    verify ipv4_checksum if(ipv4.ihl == 5);
    update ipv4_checksum if(ipv4.ihl == 5);
}

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.fragOffset, latest.protocol) {
        1 : parse_icmp;
        6 : parse_tcp;
        17 : parse_udp;
        47 : parse_gre;

        default: parse_payload;
    }
}

header ipv6_t ipv6;

parser parse_ipv6 {
    extract(ipv6);
    return select(latest.nextHdr) {
        58 : parse_icmpv6;
        6 : parse_tcp;
        17 : parse_udp;
        47 : parse_gre;

        default: parse_payload;
    }
}

header icmp_t icmp;

parser parse_icmp {
    extract(icmp);
    return parse_payload;
}

header icmpv6_t icmpv6;

parser parse_icmpv6 {
    extract(icmpv6);
    return parse_payload;
}

header tcp_t tcp;

parser parse_tcp {
    extract(tcp);
    return parse_payload;
}






header udp_t udp;

header roce_v2_header_t roce_v2;

parser parse_roce_v2 {
    extract(roce_v2);
    return parse_payload;
}

parser parse_udp {
    extract(udp);
    return select(latest.dstPort) {
        4789 : parse_vxlan;
        6081: parse_geneve;
        1021: parse_roce_v2;
        default: parse_payload;
    }
}

header sctp_t sctp;

parser parse_sctp {
    extract(sctp);
    return parse_payload;
}
header gre_t gre;
parser parse_gre {
    extract(gre);

    return select(latest.K, latest.proto) {
        0x6558 : parse_nvgre;

        0x88BE : parse_erspan_v1;
        0x22EB : parse_erspan_v2;
        0x894f : parse_nsh;
        default: parse_payload;
    }
}

header nvgre_t nvgre;
header ethernet_t inner_ethernet;

header ipv4_t inner_ipv4;
header ipv6_t inner_ipv6;
header ipv4_t outer_ipv4;
header ipv6_t outer_ipv6;

field_list inner_ipv4_checksum_list {
        inner_ipv4.version;
        inner_ipv4.ihl;
        inner_ipv4.diffserv;
        inner_ipv4.totalLen;
        inner_ipv4.identification;
        inner_ipv4.flags;
        inner_ipv4.fragOffset;
        inner_ipv4.ttl;
        inner_ipv4.protocol;
        inner_ipv4.srcAddr;
        inner_ipv4.dstAddr;
}

field_list_calculation inner_ipv4_checksum {
    input {
        inner_ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field inner_ipv4.hdrChecksum {
    verify inner_ipv4_checksum if(valid(ipv4));
    update inner_ipv4_checksum if(valid(ipv4));
}

header udp_t outer_udp;

parser parse_nvgre {
    extract(nvgre);
    return parse_inner_ethernet;
}

header erspan_header_v1_t erspan_v1_header;

parser parse_erspan_v1 {
    extract(erspan_v1_header);
    return parse_payload;
}

header erspan_header_v2_t erspan_v2_header;

parser parse_erspan_v2 {
    extract(erspan_v2_header);
    return parse_payload;
}



header arp_rarp_t arp_rarp;

parser parse_arp_rarp {
    extract(arp_rarp);
    return select(latest.protoType) {
        0x0800 : parse_arp_rarp_ipv4;
        default: parse_payload;
    }
}

header arp_rarp_ipv4_t arp_rarp_ipv4;

parser parse_arp_rarp_ipv4 {
    extract(arp_rarp_ipv4);
    return parse_payload;
}

header eompls_t eompls;

parser parse_eompls {
    extract(eompls);
    extract(inner_ethernet);
    return parse_payload;
}

header vxlan_t vxlan;

parser parse_vxlan {
    extract(vxlan);
    return parse_inner_ethernet;
}

header genv_t genv;

header genv_opt_A_t genv_opt_A;
header genv_opt_B_t genv_opt_B;
header genv_opt_C_t genv_opt_C;

parser parse_geneve {
    extract(genv);







    return parse_genv_inner;
}
parser parse_genv_inner {
    return select(genv.protoType) {
        0x6558 : parse_inner_ethernet;
        0x0800 : parse_inner_ipv4;
        0x86dd : parse_inner_ipv6;
        default : parse_payload;
    }
}

header nsh_t nsh;
header nsh_context_t nsh_context;

parser parse_nsh {
    extract(nsh);
    extract(nsh_context);
    return select(nsh.protoType) {
        0x0800 : parse_inner_ipv4;
        0x86dd : parse_inner_ipv6;
        0x6558 : parse_inner_ethernet;
        default: parse_payload;
    }
}

parser parse_inner_ipv4 {
    extract(inner_ipv4);
    return select(latest.fragOffset, latest.protocol) {
        1 : parse_inner_icmp;
        6 : parse_inner_tcp;
        17 : parse_inner_udp;

        default: parse_payload;
    }
}

header icmp_t inner_icmp;

parser parse_inner_icmp {
    extract(inner_icmp);
    return parse_payload;
}

header tcp_t inner_tcp;

parser parse_inner_tcp {
    extract(inner_tcp);
    return parse_payload;
}

header udp_t inner_udp;

parser parse_inner_udp {
    extract(inner_udp);
    return parse_payload;
}

header sctp_t inner_sctp;

parser parse_inner_sctp {
    extract(inner_sctp);
    return parse_payload;
}

parser parse_inner_ipv6 {
    extract(inner_ipv6);
    return select(latest.nextHdr) {
        58 : parse_inner_icmpv6;
        6 : parse_inner_tcp;
        17 : parse_inner_udp;

        default: parse_payload;
    }
}

header icmpv6_t inner_icmpv6;

parser parse_inner_icmpv6 {
    extract(inner_icmpv6);
    return parse_payload;
}

parser parse_inner_ethernet {
    extract(inner_ethernet);
    return select(latest.etherType) {
        0x0800 : parse_inner_ipv4;
        0x86dd : parse_inner_ipv6;
        default: parse_payload;
    }
}

header_type payload_t {
    fields {
        data : 8;
    }
}
header payload_t data;


parser parse_payload {
    extract(data);
    return ingress;
}

action mark_forward() {
    //data.data = 255; //Ali
    //standard_metadata.egress_spec = 10;
    modify_field(data.data, 255);
    modify_field(standard_metadata.egress_spec, 10);


}

table mark_check {
    reads {
        data.data : exact;
    }
    actions {
        mark_forward;
    }
    //default_action: mark_forward; //Ali
}

control ingress { apply(mark_check); }
