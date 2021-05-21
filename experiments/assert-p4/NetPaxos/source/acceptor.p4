#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/paxos_headers.p4"
#include "includes/paxos_parser.p4"


header_type ingress_metadata_t {
    fields {
        round : ROUND_SIZE;
        set_drop : 1;
    }
}

metadata ingress_metadata_t local_metadata;

register datapath_id {
    width: DATAPATH_SIZE;
    static : acceptor_tbl;
    instance_count : 1;
}

register rounds_register {
    width : ROUND_SIZE;
    instance_count : INSTANCE_COUNT;
}

register vrounds_register {
    width : ROUND_SIZE;
    instance_count : INSTANCE_COUNT;
}

register values_register {
    width : VALUE_SIZE;
    instance_count : INSTANCE_COUNT;
}

action _nop() {

}

action _drop() {
    drop();
}

// Copying Paxos-fields from the register to meta-data structure. The index
// (i.e., paxos instance number) is read from the current packet. Could be
// problematic if the instance exceeds the bounds of the register.
action read_round() {
    register_read(local_metadata.round, rounds_register, paxos.inst);
    modify_field(local_metadata.set_drop, 1);
}

table round_tbl {
    actions { read_round; }
    size : 1;
}

// Receive Paxos 1A message, send Paxos 1B message
action handle_1a(learner_port) {
    modify_field(paxos.msgtype, PAXOS_1B);                          // Create a 1B message
    register_read(paxos.vrnd, vrounds_register, paxos.inst);        // paxos.vrnd = vrounds_register[paxos.inst]
    register_read(paxos.paxosval, values_register, paxos.inst);     // paxos.paxosval  = values_register[paxos.inst]
    register_read(paxos.acptid, datapath_id, 0);                    // paxos.acptid = datapath_id
    register_write(rounds_register, paxos.inst, paxos.rnd);         // rounds_register[paxos.inst] = paxos.rnd
    modify_field(udp.dstPort, learner_port);
    modify_field(udp.checksum, 0);
}

// Receive Paxos 2A message, send Paxos 2B message
action handle_2a(learner_port) {
    modify_field(paxos.msgtype, PAXOS_2B);				            // Create a 2B message
    register_write(rounds_register, paxos.inst, paxos.rnd);         // rounds_register[paxos.inst] = paxos.rnd
    register_write(vrounds_register, paxos.inst, paxos.rnd);        // vrounds_register[paxos.inst] = paxos.rnd
    register_write(values_register, paxos.inst, paxos.paxosval);    // values_register[paxos.inst] = paxos.paxosval
    register_read(paxos.acptid, datapath_id, 0);                    // paxos.acptid = datapath_id
    modify_field(udp.dstPort, learner_port);
    modify_field(udp.checksum, 0);
}

table acceptor_tbl {
    reads   { paxos.msgtype : exact; }
    actions { handle_1a; handle_2a; _drop; }
}

action forward(port) {
    modify_field(standard_metadata.egress_spec, port);
}

table forward_tbl {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
        forward;
        _drop;
    }
    size : 48;
}

table drop_tbl {
    reads {
        local_metadata.set_drop : exact;
    }
    actions { _drop; _nop; }
    size : 2;
}

control ingress {
    if (valid(ipv4)) {
        apply(forward_tbl);
    }

    if (valid(paxos)) {
        apply(round_tbl);
        if (local_metadata.round <= paxos.rnd) {
            apply(acceptor_tbl);
        }
    }
}

control egress {
    apply(drop_tbl);
}