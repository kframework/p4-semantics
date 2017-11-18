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

action inc(){
    register_read(meta.reg_val,reg,0);
    add(meta.reg_val,meta.reg_val,1);
    register_write(reg,0,meta.reg_val);
    modify_field(standard_metadata.egress_spec, 0);
}

table inc_reg_table{
    reads{
        meta.valid : exact;
    }
    actions{
        inc;
    }
}


control ingress{
    apply(inc_reg_table);
}