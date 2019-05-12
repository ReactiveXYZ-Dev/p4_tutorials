/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
// #include <psa.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

struct pkt_drop_digest_t {
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    pkt_drop_digest_t pkt_drop_msg;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        // modify dropped digest
        meta.pkt_drop_msg.srcAddr = hdr.ipv4.srcAddr;
        meta.pkt_drop_msg.dstAddr = hdr.ipv4.dstAddr;
        // send
        digest<pkt_drop_digest_t>((bit<32>)1024, meta.pkt_drop_msg);

        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    apply {
        // if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        // }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

// #include <core.p4>
// #include <v1model.p4>

// typedef bit<9> PortId_t;

// header ethernet_t {
//     bit<48> dstAddr;
//     bit<48> srcAddr;
//     bit<16> ethType;
// }

// header ipv4_t {
//     bit<4>  version;
//     bit<4>  ihl;
//     bit<8>  diffserv;
//     bit<16> ipv4_length;
//     bit<16> id;
//     bit<3>  flags;
//     bit<13> offset;
//     bit<8>  ttl;
//     bit<8>  protocol;
//     bit<16> checksum;
//     bit<32> srcAddr;
//     bit<32> dstAddr;
// }

// struct metadata {
// }

// struct headers {
//     ethernet_t eth;
//     ipv4_t     ipv4;
// }

// parser ParserImpl(packet_in packet,
//     out headers hdr,
//     inout metadata meta,
//     inout standard_metadata_t standard_metadata)
// {
//     state start {
//         transition parse_eth;
//     }
//     state parse_eth {
//         packet.extract(hdr.eth);
//         transition select(hdr.eth.ethType) {
//             0x800: parse_ipv4;
//             default: accept;
//         }
//     }
//     state parse_ipv4 {
//         packet.extract(hdr.ipv4);
//         transition accept;
//     }
// }

// control egress(inout headers hdr,
//     inout metadata meta,
//     inout standard_metadata_t standard_metadata)
// {
//     apply { }
// }

// struct mac_learn_digest {
//     bit<48> srcAddr;
//     bit<9>  ingress_port;
// }

// control ingress(inout headers hdr,
//     inout metadata meta,
//     inout standard_metadata_t standard_metadata)
// {
//     action nop() { }
//     action generate_learn_notify() {

//         // Current p4c does not allow operations inside digest() call
//         // in runs when generating P4Info file, e.g. like this:

//         // p4test --p4runtime-format json --p4runtime-file prog1.json prog1.p4

//         // For example, it gives an error if I try to do '& 0xff'
//         // after ingress_port.  It also gives an error if I try to
//         // replace 'standard_metadata.ingress_port' with a constant
//         // like 0xff.

//         // The names in P4Info file currently are generated from the
//         // fields below, not from the names of the member fields of
//         // struct mac_learn_digest.
        
//         digest<mac_learn_digest>((bit<32>) 1024,
//             { hdr.eth.srcAddr,
//               standard_metadata.ingress_port
//             });
//     }
//     action action_with_parameters(PortId_t port, bit<48> new_dest_mac) {
//         standard_metadata.egress_port = port;
//         hdr.eth.dstAddr = new_dest_mac;
//     }
//     table learn_notify {
//         key = {
//             standard_metadata.ingress_port : exact;
//             hdr.eth.srcAddr                : exact;
//         }
//         actions = {
//             nop;
//             generate_learn_notify;
//             action_with_parameters;
//         }
//     }
//     apply {
//         learn_notify.apply();
//     }
// }

// control DeparserImpl(packet_out packet, in headers hdr) {
//     apply {
//         packet.emit(hdr.eth);
//         packet.emit(hdr.ipv4);
//     }
// }

// control verifyChecksum(inout headers hdr, inout metadata meta) {
//     apply { }
// }

// control computeChecksum(inout headers hdr, inout metadata meta) {
//     apply { }
// }

// V1Switch(ParserImpl(),
//     verifyChecksum(),
//     ingress(),
//     egress(),
//     computeChecksum(),
//     DeparserImpl()) main;
