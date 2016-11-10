calculated_field tcp.chksum {
        update tcpv4_calc if (valid(ipv4));
        update tcpv6_calc if (valid(ipv6));
        verify tcpv4_calc if (valid(ipv4));
        verify tcpv6_calc if (valid(ipv6));
}