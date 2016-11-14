header_type local_metadata_t {
    fields {
        cpu_code        : 16; // Code for packet going to CPU
        port_type       : 4;  // Type of port: up, down, local...
        ingress_error   : 1;  // An error in ingress port check
        was_mtagged     : 1;  // Track if pkt was mtagged on ingr
        copy_to_cpu     : 1;  // Special code resulting in copy to CPU
        bad_packet      : 1;  // Other error indication
    }
}