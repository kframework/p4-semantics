header_type meta_t {
    fields {
        reg_val : 8;
    }
}

metadata meta_t meta;


parser start{
    return ingress;
}

register reg {
    width: 8;
    instance_count: 1;
}

action read_reg(){
    register_read(meta.reg_val,reg,0);
}

table read_reg_table{
    reads{
        meta.valid : exact;
    }
    actions{
        read_reg;
    }
}


action balance(port,val){
    modify_field(standard_metadata.egress_spec, port);
    register_write(reg, 0, val);
}

table balance_table{
    reads{
        meta.reg_val  : exact;
    }
    actions{
        balance;
    }
}


control ingress{
    apply(read_reg_table);
    apply(balance_table);
}