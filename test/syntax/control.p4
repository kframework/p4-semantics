// The ingress control function
control ingress {
    // Verify mTag state and port are consistent
    apply(check_mtag);
    apply(identify_port);
    apply(select_output_port);
    apply(egress_meter) {
        hit { // If egress meter table matched, apply policy
            apply(meter_policy);
        }
    }
    apply(routing_table) {
        ipv4_route_action { // IPv4 action was used
            apply(v4_rpf);
            apply(v4_acl);
        }
        ipv6_route_action { // IPv6 action was used
            apply(v6_option_check);
            apply(v6_acl);
        }
        default { // Some other action was used
            if (standard_metadata.ingress_port == 1) {
                apply(cpu_ingress_check);
            }
        }
    }
}


