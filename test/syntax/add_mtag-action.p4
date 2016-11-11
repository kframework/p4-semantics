// Add an mTag to the packet; select egress spec based on up1
 action add_mTag(up1, up2, down1, down2) {
     add_header(mtag);
     // Copy VLAN ethertype to mTag
     modify_field(mtag.ethertype, vlan.ethertype);
     // Set VLAN’s ethertype to signal mTag
     modify_field(vlan.ethertype, 0xaaaa);
     // Add the tag source routing information
     modify_field(mtag.up1, up1);
     modify_field(mtag.up2, up2);
     modify_field(mtag.down1, down1);
     modify_field(mtag.down2, down2);
     // Set the destination egress port as well from the tag info
     modify_field(standard_metadata.egress_spec, up1);
 }